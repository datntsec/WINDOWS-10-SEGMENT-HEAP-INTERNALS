WINDOWS 10 SEGMENT HEAP INTERNALS
-

# ABSTRACT
Được ra mắt trong Windows 10, Segment Heap triển khai native heap được sử dụng trong các ứng dụng Windows (trước đây được gọi là Modern/Metro apps) và các tiến trình hệ thống nhất định. Việc triển khai heap mới này là một sự bổ sung được nghiên cứu kỹ lưỡng và được tài liệu hóa rộng rãi để NT Heap vẫn được sử dụng trong các ứng dụng truyền thống và trong các loại phân bổ nhất định trong các ứng dụng Windows.

Một khía cạnh quan trọng của Segment Heap là nó được thiết lập cho Microsoft Edge, có nghĩa là các components/dependencies chạy trong Edge không sử dụng trình quản lý heap tùy chỉnh mà sẽ sử dụng Segment Heap. Do đó, việc khai thác các lỗ hổng memory corruption đáng tin cậy trong các components/dependencies Edge này sẽ yêu cầu một số mức độ hiểu biết về Segment Heap.

Trong phần trình bày này, tôi sẽ thảo luận về cấu trúc dữ liệu, thuật toán và cơ chế bảo mật của Segment Heap. Kiến thức về Segment Heap cũng được áp dụng bằng cách thảo luận và chứng minh cách lỗ hổng memory corruption trong thư viện Microsoft WinRT PDF (CVE-2016-0117) được tận dụng để ghi tùy ý trong phần sau của nội dung tiến trình Edge.

# CONTENTS
1. Introduction
2. Internals
    * 2.1 Overview 
      - Architecture
      - Defaults and Configuration
      - Heap Creation
      - HeapBase and _SEGMENT_HEAP Structure
      - Block Allocation 
      - Block Freeing 
    * 2.2. Backend Allocation
      - Segment Structure
      - _HEAP_PAGE_SEGMENT Structure
      - _HEAP_PAGE_RANGE_DESCRIPTOR Structure
      - Backend Free Tree 
      - Backend Allocation 
      - Backend Freeing 
    * 2.3. Variable Size Allocation
      - VS Subsegments
      - _HEAP_VS_CONTEXT Structure 
      - _HEAP_VS_SUBSEGMENT Structure
      - _HEAP_VS_CHUNK_HEADER Structure
      - _HEAP_VS_CHUNK_FREE_HEADER Structure
      - VS Free Tree
      - VS Allocation
      - VS Freeing
    * 2.4. Low Fragmentation Heap
      - LFH Subsegments
      - _HEAP_LFH_CONTEXT Structure
      - _HEAP_LFH_ONDEMAND_POINTER Structure.
      - _HEAP_LFH_BUCKET Structure
      - _HEAP_LFH_AFFINITY_SLOT Structure 
      - _HEAP_LFH_SUBSEGMENT_OWNER Structure 
      - _HEAP_LFH_SUBSEGMENT Structure
      - LFH Block Bitmap 
      - LFH Bucket Activation
      - LFH Allocation
      - LFH Freeing 
    * 2.5. Large Blocks Allocation 
      - _HEAP_LARGE_ALLOC_DATA Structure
      - Large Block Allocation
      - Large Block Freeing
    * 2.6. Block Padding
    * 2.7. Summary and Analysis: Internals
3. Security Mechanisms
    * 3.1. Fast Fail on Linked List Node Corruption
    * 3.2. Fast Fail on RB Tree Node Corruption
    * 3.3. Heap Address Randomization
    * 3.4. Guard Pages 
    * 3.5. Function Pointer Encoding 
    * 3.6. VS Block Header Encoding
    * 3.7. LFH Subsegment BlockOffsets Encoding
    * 3.8. LFH Allocation Randomization
    * 3.9. Summary and Analysis: Security Mechanisms
4. Case Study
    * 4.1. CVE-2016-0117 Vulnerability Details 
    * 4.2. Plan for Implanting the Target Address
    * 4.3. Manipulating the MSVCRT Heap with Chakra’s ArrayBuffer 
      - Allocation and Setting Controlled Values
      - LFH Bucket Activation
      - Freeing and Garbage Collection 
    * 4.4. Preventing Target Address Corruption
    * 4.5. Preventing Free Blocks Coalescing
    * 4.6. Preventing Unintended Use of Free Blocks
    * 4.7. Adjusted Plan for Implanting the Target Address
    * 4.8. Successful Arbitrary Write
    * 4.9. Analysis and Summary: Case Study
5. Conclusion
6. Appendix: WinDbg !heap Extension Commands for Segment Heap
    * !heap -x <address>
    * !heap -i <address> -h <heap>
    * !heap -s -a -h <heap>
7. Bibliography
  
## 1. INTRODUCTION
Với sự ra đời của Windows 10, Segment Heap, một triển khai native heap mới cũng được giới thiệu. Nó hiện là triển khai native heap được sử dụng trong các ứng dụng Windows (trước đây được gọi là Modern/Metro apps) và trong các tiến trình hệ thống nhất định, các ứng dụng truyền thống thì mặc định vẫn triển khai native heap cũ hơn (NT Heap).

Từ quan điểm của nhà nghiên cứu bảo mật, việc hiểu rõ internals của Segment Heap là rất quan trọng vì những kẻ tấn công có thể tận dụng hoặc khai thác các thành phần mới và quan trọng này trong tương lai gần, đặc biệt là vì nó đang được sử dụng bởi trình duyệt Edge. Ngoài ra, một nhà nghiên cứu bảo mật thực hiện kiểm tra phần mềm có thể cần phải phát triển một proof of concept (POC - bằng chứng về khái niệm) cho một lỗ hổng để chứng minh khả năng khai thác vendor/developer. Nếu việc tạo bằng chứng của khái niệm (POC) yêu cầu thao tác chính xác đối với một heap được quản lý bởi Segment Heap, thì sự hiểu biết về internals của nó chắc chắn sẽ hữu ích. Bài viết này nhằm giúp người đọc hiểu sâu sắc về Segment Heap.

Bài viết được chia làm ba phần chính. Phần thứ nhất (Internals) sẽ bàn luận sâu về các component (thành phần) khác nhau của Segment Heap. Nó bao gồm các cấu trúc dữ liệu và thuật toán được sử dụng bởi mỗi Segment Heap component khi thực hiện các chức năng của chúng. Phần thứ hai (Security Mechanisms) sẽ bàn luận về các cơ chế khác nhau khiến việc tấn công Segment Heap metadata quan trọng trở nên khó khăn hoặc không thể tin cậy và trong một số trường hợp nhất định, gây khó khăn cho việc thực hiện thao tác bố trí heap chính xác. Phần thứ ba (Case Study) là nơi áp dụng sự hiểu biết về Segment Heap bằng cách thảo luận về các phương pháp để điều khiển việc bố trí heap được quản lý bởi Segment để tận dụng lỗ hổng ghi tùy ý.

Vì Segment Heap và NT Heap chia sẻ các khái niệm tương tự nhau, người đọc được khuyến khích đọc các tác phẩm trước đây thảo luận về Internals của NT Heap [1, 2, 3, 4, 5]. Các công trình trước đây và các bài báo/bài thuyết trình khác nhau mà họ tham khảo cũng thảo luận về các cơ chế bảo mật và kỹ thuật tấn công cho NT Heap sẽ cung cấp cho người đọc ý tưởng tại sao các cơ chế bảo mật heap nhất định lại được sử dụng trong Segment Heap

Tất cả các thông tin trong bài viết này dưa trên NTDLL.DLL (64-bit) phiên bản 10.0.14295.1000 từ Windows 10 Redstone 1 Preview (Build 14295).

## 2. INTERNALS
Trong phần này, sẽ bàn sâu về internals của Segment Heap. Đầu tiên sẽ là tổng quan về các thành phần khác nhau của Segment Heap và sau đó mô tả các trường hợp khi Segment Heap được kích hoạt. Sau phần tổng quan, mỗi thành phần Segment Heap sẽ được thảo luận chi tiết trong phần phụ của riêng chúng.

Lưu ý rằng. internal NTDLL functions được bàn luận ở đây có thể được nêu trong một số bản dựng NTDLL. Do đó, các internal functions có thể không được nhìn thấy trong danh sách các functions trong IDA và bản sao của các function có thể được nhúng/gắn vào trong các functions khác.

### 2.1. OVERVIEW
**Architecture**

Segment Heap bao gồm bốn components (thành phần): (1) Backend, phân bổ các heap block có kích thước > 128KB và <= 508KB. Nó sử dụng các virtual memory functions do NT Memory Manager cung cấp để tạo và quản lý các segment ở nơi các backend block được cấp phát từ đó. (2) Thành phần phân bổ variable size (VS) cho các yêu cầu cấp phát kích thước <= 128KB. Nó sử dụng backend để tạo các VS subsegments ở nơi các VS block được cấp phát từ đó. (3) Low Fragmentation Heap (LFH) cho các yêu cầu cấp phát có kích thước <= 16.368 byte nhưng chỉ khi kích thước phân bổ được phát hiện là thường được sử dụng trong việc cấp phát. Nó sử dụng backend để tạo các phân đoạn LFH subsegments nơi các LFH block được cấp phát từ dó. (4) Sử dụng để phân bổ các block > 508KB. Nó sử dụng các chức năng bộ nhớ ảo do NT Memory Manager cung cấp để phân bổ và giải phóng các khối lớn. Nó sử dụng virtual memory functions cho việc cấp phát và giải phóng các block lớn.

![](pic/pic1.PNG)

**Defaults and Configuration**

Segment Heap hiện là một tính năng tự lựa chọn tham gia. Các ứng dụng Windows được chọn tham gia theo mặc định và các tệp thực thi có tên khớp với bất kỳ tên nào sau đây (tên của tệp thực thi hệ thống) cũng được chọn tham gia theo mặc định để sử dụng Segment Heap:
- csrss.exe
- lsass.exe
- runtimebroker.exe
- services.exe
- smss.exe
- svchost.exe

Để bật hoặc tắt Segment Heap cho một tệp thực thi cụ thể, có thể Image File Execution Options (IFEO) thiết lập registry entry như sau:
``` 
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\
Image File Execution Options\(executable)
FrontEndHeapDebugOptions = (DWORD)
Bit 2 (0x04): Disable Segment Heap
Bit 3 (0x08): Enable Segment Heap
```

Để bật hoặc tắt Segment Heap cho toàn bộ file thực thi, có thể thiết lập registry entry như sau:
```
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Segment Heap
Enabled = (DWORD)
0 : Disable Segment Heap
(Not 0): Enable Segment Heap
```

Nếu sau tất cả các lần kiểm tra, nó được xác định rằng một quá trình sẽ sử dụng Segment Heap, bit 0 của biến toàn cục RtlpHpHeapFeatures sẽ được đặt.

Lưu ý rằng ngay cả khi Segment Heap được bật trong một tiến trình, không phải tất cả các heap được tạo bởi tiến trình đó sẽ được quản lý bởi Segment Heap vì có những loại heap đặc biệt vẫn cần được quản lý bởi NT Heap (điều này sẽ được thảo luận trong mục con tiếp theo).

**Heap Creation**



![](pic/pic1.PNG)
![](pic/pic1.PNG)
![](pic/pic1.PNG)
![](pic/pic1.PNG)
![](pic/pic1.PNG)
![](pic/pic1.PNG)
![](pic/pic1.PNG)
![](pic/pic1.PNG)
![](pic/pic1.PNG)
![](pic/pic1.PNG)
![](pic/pic1.PNG)
![](pic/pic1.PNG)
![](pic/pic1.PNG)
![](pic/pic1.PNG)
![](pic/pic1.PNG)
![](pic/pic1.PNG)

