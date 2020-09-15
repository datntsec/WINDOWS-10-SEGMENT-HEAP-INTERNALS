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

Segment Heap bao gồm bốn components (thành phần): (1) Backend, phân bổ các heap block có kích thước > 128KB và <= 508KB. Nó sử dụng các virtual memory functions do NT Memory Manager cung cấp để tạo và quản lý các segment ở nơi các backend block được cấp phát từ đó. (2) Thành phần phân bổ variable size (VS) cho các yêu cầu cấp phát kích thước <= 128KB. Nó sử dụng backend để tạo các VS subsegments ở nơi các VS block được cấp phát từ đó. (3) Low Fragmentation Heap (LFH) cho các yêu cầu cấp phát có kích thước <= 16.368 byte nhưng chỉ khi kích thước phân bổ được phát hiện là thường được sử dụng trong việc cấp phát. Nó sử dụng backend để tạo các phân đoạn LFH subsegments nơi các LFH block được cấp phát từ dó. (4) Sử dụng để phân bổ các block > 508KB. Nó sử dụng các virtual memory functions do NT Memory Manager cung cấp để cấp phát và giải phóng các block lớn.

![](pic/pic1.PNG)

**Defaults and Configuration**

Segment Heap hiện là một tính năng opt-in. Các ứng dụng Windows được opt-in theo mặc định và các tệp thực thi có tên khớp với bất kỳ tên nào sau đây (tên của tệp thực thi hệ thống) cũng được opt-in theo mặc định để sử dụng Segment Heap:
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

Nếu Segment Heap được thiết lập (bit 0 của RtlpHpHeapFeatures được set), heap được tạo bởi [HeapCreate()](https://docs.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heapcreate) sẽ được quản lý bởi Segment Heap ngoại trừ đối số dwMaximumSize được truyền vào nó không phải là 0 (heap không thể phát triển kích thước)

Nếu [RtlCreateHeap()](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlcreateheap) API được sử dụng trực tiếp để tạo heap, tất cả các điều sau đây phải đúng đối với Segment Heap để quản lý heap được tạo:
   - Heap phải có thể phát triển: Đối số Flags được truyền vào hàm RtlCreateHeap() phải là HEAP_GROWABLE.
   - Bộ nhớ heap không nên được cấp phát trước (đề xuất một heap được chia sẻ): Đối số HeapBase được truyền đến RtlCreateHeap() phải là NULL.
   - Nếu đối số Parameters được truyền đến RtlCreateHeap(), các trường Parameters sau đây phải được đặt thành 0/NULL: SegmentReserve, SegmentCommit, VirtualMemoryThreshold and CommitRoutine.
   - Đối số Lock được truyền vào hàm RtlCreateHeap() phải là NULL.
   
Hình minh họa sau đây sẽ cho thấy heap được tạo khi nội dung tiến trình Edge (một app của Windows) được load lần đầu:

![](pic/pic2.PNG)

Bốn trên năm heap được quản lý bởi Segment Heap. Heap đầu tiên là tiến trình heap mặc định, và heap thứ ba là MSVCRT heap (msvcrt!crtheap). Heap thứ hai là một shared heap (ntdll!CsrPortHeap) nên nó được quản lý bởi NT Heap.

**HeapBase and _SEGMENT_HEAP Structure**

Khi một heap được quản lý bởi Segment Heap được tạo, address/handle heap (gọi chung là HeapBase) được trả về bởi HeapCreate() hoặc RtlCreateHeap() sẽ trỏ đến một cấu trúc _SEGMENT_HEAP (bản sao cấu trúc _HEAP của NT Heap).

HeapBase là vị trí trung tâm, lưu trữ trạng thái của các components Segment Heap khác nhau, nó có các trường sau:
```
windbg> dt ntdll!_SEGMENT_HEAP
   +0x000 TotalReservedPages : Uint8B
   +0x008 TotalCommittedPages : Uint8B
   +0x010 Signature : Uint4B
   +0x014 GlobalFlags : Uint4B
   +0x018 FreeCommittedPages : Uint8B
   +0x020 Interceptor : Uint4B
   +0x024 ProcessHeapListIndex : Uint2B
   +0x026 GlobalLockCount : Uint2B
   +0x028 GlobalLockOwner : Uint4B
   +0x030 LargeMetadataLock : _RTL_SRWLOCK
   +0x038 LargeAllocMetadata : _RTL_RB_TREE
   +0x048 LargeReservedPages : Uint8B
   +0x050 LargeCommittedPages : Uint8B
   +0x058 SegmentAllocatorLock : _RTL_SRWLOCK
   +0x060 SegmentListHead : _LIST_ENTRY
   +0x070 SegmentCount : Uint8B
   +0x078 FreePageRanges : _RTL_RB_TREE
   +0x088 StackTraceInitVar : _RTL_RUN_ONCE
   +0x090 ContextExtendLock : _RTL_SRWLOCK
   +0x098 AllocatedBase : Ptr64 UChar
   +0x0a0 UncommittedBase : Ptr64 UChar
   +0x0a8 ReservedLimit : Ptr64 UChar
   +0x0b0 VsContext : _HEAP_VS_CONTEXT
   +0x120 LfhContext : _HEAP_LFH_CONTEXT
 ```
 
   - Signature - 0xDDEEDDEE (Heap được tạo bởi Segment Heap)
   
Các trường để theo dõi trạng thái phân bổ block lớn (ở phần 2.5 ta sẽ nói thêm):
   - LargeAllocMetadata - Red-black tree (RB tree) của large blocks metadata.
   - LargeReservedPages - Số trang được dành riêng cho tất cả large blocks allocation.
   - LargeCommittedPages - Số trang được commit cho tất cả large blocks allocation.

Các trường để theo dõi trạng thái phân bộ backend (ở phần 2.2 ta sẽ nói thêm):
   - SegmentCount - Số lượng segment thuộc sở hữu bởi heap.
   - SegmentListHead - Danh sách liên kết của các segment thuộc sở hưu của heap.
   - FreePageRanges - RB tree của free backend blocks.
   
Cấu trúc con sau theo dõi trạng thái của sự thay đổi kích thước phần bổ và trạng thái của Low Fragmentation Heap:
   - VsContext - Theo dõi trạng thái của sự thay đổi kích thước phần bổ (xem thêm ở phần 2.3).
   - LfhContext - Theo dõi trạng thái của Low Fragmentation Heap (xem thêm ở phần 2.4).
   
Heap được cấp phát và khởi tạo thông qua lệnh gọi hàm RtlpHpSegHeapCreate(). NtAllocateVirtualMemory () được sử dụng để reverse và commit bộ nhớ ảo cho heap. Kích thước reverse thay đổi tùy thuộc vào số lượng bộ xử lý và kích thước commit là kích thước của cấu trúc _SEGMENT_HEAP.

Phần còn lại của bộ nhớ reverse dưới cấu trúc _SEGMENT_HEAP được gọi là LFH context extension và nó được dynamically commited để lưu trữ cấu trúc dữ liệu cần thiết cho các LFH bucket đã được kích hoạt.

![](pic/pic3.PNG)

**Block Allocation**

Khi cấp phát một block thông qua HeapAlloc() hoặc RtlAllocateHeap(), hàm RtlpHpAllocateHeap() sẽ được gọi cuối cùng để thực hiện yêu cầu cấp phát nếu heap được quản lý bởi Segment Heap

RtlpHpAllocateHeap() có các đối số sau:
```
PVOID RtlpHpAllocateHeap(_SEGMENT_HEAP* HeapBase, SIZE_T UserSize, ULONG Flags, USHORT Unknown)
```

Trong đó UserSize (kích thước do người dùng yêu cầu) là kích thước được truyền vào hàm HeapAlloc() hoặc RtlAllocateHeap(). Giá trị trả về là con trỏ đến block mới được cấp phát (được gọi là UserAddress).

Sơ đồ sau miêu tả logic của RtlpHpAllocateHeap():

![](pic/pic4.PNG)

Mục đích của RtlpHpAllocateHeap là gọi hàm cấp phát Segment Heap component thích hợp dựa trên AllocSize. AllocSize (kích thước phân bổ) là UserSize được điều chỉnh tùy thuộc vào Flags, nhưng theo mặc định, AllocSize sẽ bằng UserSize trừ khi UserSize là 0 (nếu UserSize là 0, AllocSize sẽ là 1).

Lưu ý rằng việc AllocSize được kiểm tra thực sự nằm trong hàm RtlpHpAllocateHeapInternal(). Ngoài ra, cần lưu ý là nếu phân bổ LFH trả về -1, điều đó có nghĩa là LFH bucket tương ứng với AllocSize chưa được kích hoạt và do đó, yêu cầu cấp phát cuối cùng sẽ được chuyển đến components cấp phát VS.

**Block Freeing**

Khi giải phóng một block thông qua HeapFree() hoặc RtlFreeHeap(), hàm RtlpHpFreeHeap() sẽ được gọi cuối cùng để thực hiện yêu cầu nếu heap được quản lý bởi Segment Heap.

RtlpHpFreeHeap() có các đối số sau:
```
BOOLEAN RtlpHpFreeHeap(_SEGMENT_HEAP* HeapBase, PVOID UserAddress, ULONG Flags,
 SIZE_T* UserSize, USHORT* Unknown)
```

Trong đó UserAddress là địa chỉ của block được trả về bởi HeapAlloc() hoặc RtlAllocateHeap() và UserSize sẽ là kích thước do người dùng yêu cầu của block được giải phóng.

Sơ đồ bên dưới miêu tả logic của việc giải phóng của hàm RtlpHpFreeHeap():

![](pic/pic5.PNG)

Mục đích của RtlpHpFreeHeap() là gọi hàm giải phóng của Segment Heap component thích hợp dựa trên giá trị của UserAddress và loại subsegment của nó. Các subsegment sẽ được thảo luận thêm ở phần sau của bài viết này, ở đây ta cần biết, các subsegment là các loại backend block đặc biệt, nơi các block VS và LFH được cấp phát từ đó.

Vì địa chỉ của các phân bổ lớn được căn chỉnh thành 64KB, một UserAddress với 16 bit thấp được clear sẽ được kiểm tra đầu tiên dựa trên large allocation bitmap. Nếu UserAddress (thực sự là UserAddress >> 16) được đặt trong large allocation bitmap, large block freeing được gọi.

Tiếp theo, subsegment nơi UserAddress được xác định. Nếu UserAddress nhỏ hơn hoặc bằng resulting địa chỉ của subsegment, điều đó có nghĩa là UserAddress dành cho backend block, vì địa chỉ của VS block và LFH block nằm trên địa chỉ subsegment do các header của VS/LFH subsegment được đặt trước các VS/LFH block. Nếu UserAddress trỏ đến một backend block, backend freeing được gọi.

Cuối cùng, nếu subsegment là một LFH subsegment, LFH freeing được gọi. Ngược lại, VS freeing được gọi. Nếu VS freeing được gọi và nếu LfhBlockSize được trả về (tương đương block size của VS block được giải phóng trừ đi 0x10) có thê được sử dụng bởi LFH, bộ đếm sử dụng của LFH bucket tương ứng với LfhBlockSize sẽ được cập nhật.

Lưu ý rằng logic kiểm tra subsegment của UserAddress thực sự nằm trong hàm RtlpHpSegFree(). Ngoài ra, sơ đồ chỉ hiển thị logic giải phóng của RtlpHpFreeHeap(), các chức năng khác của nó không được bao gồm.

### 2.2. BACKEND ALLOCATION 
Backend được sử dụng để phân bổ kích thước từ 131073 (0x20001) đến 520192 (0x7F000). Các backend block có mức độ chi tiết về kích thước trang và mỗi block không có block header ở đầu. Ngoài việc phân bổ các back end block, backend cũng được sử dụng bởi component VS và LFH để tạo các subsegment VS/LFH (các loại backend block đặc biệt) nơi các block VS/LFH được phân bổ.

**Segment Structure** 

Backend hoạt động trên cấu trúc segment là các block virtual memory 1MB (0x100000) được cấp phát thông qua hàm NtAllocateVirtualMemory(). Các segment được theo dõi thông qua trường SegmentListHead trong HeapBase:

![](pic/pic6.PNG)

2000 bytes đầu tiên của một segment được sử dụng cho segment header, trong khi phần còn lại được sử dụng để phân bổ các backend block. Ban đầu, 0x2000 bytes đầu tiên cộng với kích thước commit ban đầu của segment được commit, trong khi phần còn lại ở trạng thái reserver và được commit và decommit khi cần thiết.

Segment header bao gồm một mảng 256 bộ mô tả phạm vị trang được dùng để mô tả trạng thái của từng trang trong segment. Vì phần dữ liệu của segment bắt đầu tại offset 0x2000,  page range descriptor đầu tiên được định vị lại để lưu trữ cấu trúc _HEAP_PAGE_SEGMENT, trong khi page range descriptor thứ hai không được sử dụng.

**_HEAP_PAGE_SEGMENT Structure**

Như đề cập ở trên, page range descriptor đầu tiên được định vị lại để lưu trữ cấu trúc _HEAP_PAGE_SEGMENT. Nó có các trường sau:
```
windbg> dt ntdll!_HEAP_PAGE_SEGMENT
   +0x000 ListEntry : _LIST_ENTRY
   +0x010 Signature : Uint8B
 ```
   - ListEntry - Mỗi segment là một node của danh sách liên kết các segment của heap (HeapBase.SegmentListHead).
   - Signature - Được sử dụng để xác minh nếu một địa chỉ là một phần của một segment. Trường này được tính theo công thức sau: (SegmentAddress >> 0x14) ^ RtlpHeapKey ^ HeapBase ^ 0xA2E64EADA2E64EAD.

**_HEAP_PAGE_RANGE_DESCRIPTOR Structure**

Cũng được đề cập là các page range descriptor để mô tả trạng thái của từng trang trong segment. Vì backend block có thể kéo dài nhiều trang (một phạm vi trang), page range descriptor cho trang đầu tiên của backend block được đánh dấu là "first" và do đó, sẽ có các trường bổ sung được set.
```
windbg> dt ntdll!_HEAP_PAGE_RANGE_DESCRIPTOR -r
   +0x000 TreeNode : _RTL_BALANCED_NODE
   +0x000 TreeSignature : Uint4B
   +0x004 ExtraPresent : Pos 0, 1 Bit
   +0x004 Spare0 : Pos 1, 15 Bits
   +0x006 UnusedBytes : Uint2B
   +0x018 RangeFlags : UChar
   +0x019 Spare1 : UChar
   +0x01a Key : _HEAP_DESCRIPTOR_KEY
      +0x000 Key : Uint2B
      +0x000 EncodedCommitCount : UChar
      +0x001 PageCount : UChar
   +0x01a Align : UChar
   +0x01b Offset : UChar
   +0x01b Size : UChar
 ```
   - TreeNode - "first" page range descriptor của các free backend block là các node của backend free tree (HeapBase.FreePageRanges)
   - UnusedBytes - Dành cho "first" page range descriptor. Sự khác biệt giữa UserSize và block size.
   - RangeFlags - Trường bit đại diện cho loại backend block và trạng thái của trang được đại diện bởi page range descriptor.
      - 0x01: PAGE_RANGE_FLAGS_LFH_SUBSEGMENT. Dành cho "first" page range descriptor. Backend block là một LFH subsegment.
      - 0x02: PAGE_RANGE_FLAGS_COMMITED. Page được commit.
      - 0x04: PAGE_RANGE_FLAGS_ALLOCATED. Page được allocate/busy.
      - 0x08: PAGE_RANGE_FLAGS_FIRST. Page range descriptor được đánh dấu là "first".
      - 0x20: PAGE_RANGE_FLAGS_VS_SUBSEGMENT. Dành cho "first" page range descriptor. Backend block là một VS subsegment.
   - Key - Dành cho "first" page range descriptor của free backend blocks. Nó được sử dụng khi một free backend block được chèn vào backend free tree
      - Key - Key với kích thước WORD được sử dụng cho backend free tree. Byte cao là trường PageCount và byte thấp là trường EncodedCommitCount(xem thêm bên dưới).
      - EncodedCommitCount - Bitwise NOT của số trang được commit của backend block. Số lượng các trang được commit mà kfree backend block có càng lớn, thì EncodedCommitCount sẽ thấp hơn.
      - PageCount - Số trang của backend block.
   - Offset - Dành cho non-"first" page range descriptors. Offset (độ chênh lệch) của page range descriptor từ "first" page range descriptor
   - Size - Dành cho "first" page range descriptors. Như Key.PageCount (overlapping fields).

Dưới đây là hình ảnh minh họa của một segment:

![](pic/pic7.PNG)

Và dưới đây là hình ảnh minh họa của một backend block 131328 (0x20100) bytes busy và page range descriptor tương ứng ("first" page range descriptor sẽ được highlight):

![](pic/pic8.PNG)

Lưu ý rằng vì các page range descriptor mô tả các backend block được lưu trữ ở đầu segment, điều đó có nghĩa là mỗi backend block không có block header ở đầu.

**Backend Free Tree**

Backend allocation và freeing sử dụng backend free tree để tìm và lưu trữ thông tin về các free backend block.

Gốc của backend free tree được lưu trữ trong HeapBase.FreePageRanges và các node trên cây là các "first" page range descriptor của các free backend block. Key được sử dụng để chèn các node trong backend free tree là trường Key.Key của "first" page range descriptor (xem chi tiết về Key.Key ở phần trước).

Hình ảnh minh họa bên dưới là một backend free tree, trong đó có ba free backend block với kích thước lần lượt là 0x21000, 0x23000 và 0x4F000 (tất cả oage của free block đều được decommit - Key.EncodedCommitCount là 0xFF): 

![](pic/pic9.PNG)

**Backend Allocation**

Backend allocation được thực hiện thông qua hàm RtlpHpSegAlloc(), gồm các đối số như sau:
```
PVOID RtlpHpSegAlloc(_SEGMENT_HEAP* HeapBase, SIZE_T UserSize, SIZE_T AllocSize, ULONG Flags)
```
Hàm RtlpHpSegAlloc() gọi RtlpHpSegPageRangeAllocate() đầu tiên để phân bổ một backend block. Mặt khác, RtlpHpSegPageRangeAllocate() chấp nhận số lượng trang để phân bổ và trả về “first” page range descriptor của backend block được phân bổ. Sau đó, RtlpHpSegAlloc() chuyển đổi “first” page range descriptor được trả về thành địa chỉ backend block thực tế (UserAddress) làm giá trị trả về của nó.

Sơ đồ bên dưới miêu tả logic của hàm RtlpHpSegPageRangeAllocate():

![](pic/pic10.PNG)

RtlpHpSegPageRangeAllocate() trước tiên đi qua backend free tree để tìm một free backend block có thể phù hợp với phân bổ. Key tìm kiếm được sử dụng để tìm free backend block là một giá trị có kích thước WORD, trong đó BYTE cao là số page được yêu cầu và BYTE thấp là bitwise NOT của số page được yêu cầu. Điều này có nghĩa là một tìm kiếm phù hợp nhất được ưu tiên thực hiện block được commit cao nhất, rõ hơn, nếu hai hoặc nhiều free block có kích thước tương đương phù hợp nhất với kích thước cần phân bổ, thì free block được commit cao nhất sẽ được chọn để phân bổ. Nếu bất kỳ free backend blocks nào không thể phù hợp với phân bổ, một segment mới sẽ được tạo.

Vì free backend block đã chọn có thể có nhiều page hơn số page được yêu cầu, free block sẽ được tách ra trước nếu cần thông qua RtlpHpSegPageRangeSplit() và “first” page range descriptor của free block còn lại sẽ được chèn vào backend free tree .

![](pic/pic11.PNG)

Cuối cùng, trường RangeFlags của page range descriptors của block đó được cập nhật (PAGE_RANGE_FLAGS_ALLOCATED bitis set) để đánh dấu các trang của block đó là đã được cấp phát.

**Backend Freeing**

Backend Freeing được thực hiện thông qua hàm RtlpHpSegPageRangeShrink() với các đối số sau:
```
BOOLEAN RtlpHpSegPageRangeShrink(_SEGMENT_HEAP* HeapBase, _HEAP_PAGE_RANGE_DESCRIPTOR* FirstPageRangeDescriptor, ULONG NewPageCount, ULONG Flags)
```

Trong đó FirstPageRangeDescriptor là  “first” page range descriptor của backend block được giải phóng và NewPageCount bằng 0 có nghĩa là giải phóng block.

RtlpHpSegPageRangeShrink() trước tiên sẽ xóa bit PAGE_RANGE_FLAGS_ALLOCATED trong trường RangeFlags của tất cả (ngoại trừ “first”) page range descriptors mô tả backend block được giải phóng. Sau đó, nó gọi RtlpHpSegPageRangeCoalesce() để kết hợp backend block được giải phóng với các free backend block lân cận (trước và sau) và xóa bit PAGE_RANGE_FLAGS_ALLOCATED trong trường RangeFlags của “first” page range descriptor của block được giải phóng.

![](pic/pic12.PNG)

Sau đó,“first” page range descriptor của block được hợp nhất được chèn vào backend free tree để có sẵn một free block được hợp nhất để phân bổ.

### 2.3. VARIABLE SIZE ALLOCATION
Variable size (VS) allocation được sử dụng cho phân bổ với kích thước từ 1 đến 131,072 (0x20000) byte. Các VS block có độ chi tiết 16 byte và mỗi block đều có block header ở đầu.

**VS Subsegments**

VS allocation component dựa vào backend để tạo các VS subsegments nơi các VS block được cấp phát từ đó. Một VS subsegments là một loại đặc biệt của backend block trong đó RangeFlags của “first” page range descriptor có PAGE_RANGE_FLAGS_VS_SUBSEGMENT (0x20) bit set.

Dưới đây là minh họa về mối quan hệ của HeapBase, một segment và một VS subsegment:

![](pic/pic13.PNG)

**_HEAP_VS_CONTEXT Structure**

VS context structure theo dõi các free VS block, các VS subsegment và các thông tin khác liên quan đến trạng thái cấp phát VS. Nó được lưu trữ trong trường VsContext trong HeapBase và có các trường sau:
```
windbg> dt ntdll!_HEAP_VS_CONTEXT
   +0x000 Lock : _RTL_SRWLOCK
   +0x008 FreeChunkTree : _RTL_RB_TREE
   +0x018 SubsegmentList : _LIST_ENTRY
   +0x028 TotalCommittedUnits : Uint8B
   +0x030 FreeCommittedUnits : Uint8B
   +0x038 BackendCtx : Ptr64 Void
   +0x040 Callbacks : _HEAP_SUBALLOCATOR_CALLBACKS
```
   - FreeChunkTree - RB tree của free VS blocks.
   - SubsegmentList - Danh sách liên kết chứa tất cả các VS subsegment.
   - BackendCtx - trỏ đến cấu trúc _SEGMENT_HEAP (HeapBase).
   - Callbacks - Encoded (xem thêm ở phần 3.5) callbacks được sử dụng để quản lý các VS subsegment.
   
**_HEAP_VS_SUBSEGMENT Structure**
Các VS subsegment là nơi các VS block được cấp phát. Các VS subsegment được cấp phát và khởi tạo thông qua hàm RtlpHpVsSubsegmentCreate() và sẽ có cấu trúc _HEAP_VS_SUBSEGMENT sau làm header:
```
windbg> dt ntdll!_HEAP_VS_SUBSEGMENT
   +0x000 ListEntry : _LIST_ENTRY
   +0x010 CommitBitmap : Uint8B
   +0x018 CommitLock : _RTL_SRWLOCK
   +0x020 Size : Uint2B
   +0x022 Signature : Uint2B
 ```
   - Listentry - Mỗi VS subsegment là một node của danh sách liên kết các VS subsegment (VsContext.SubsegmentList).
   - CommitBitmap - Commit bitmap của VS subsegment pages.
   - Size - Size của the VS subsegment (trừ đi 0x30 cho VS subsegment header) trong 16-byte blocks.
   - Signature - Được sử dụng để kiểm tra xem VS subsegment có bị corrupt. Được tính toán bằng: Size ^ 0xABED. 
   
Dưới đây là một minh họa về một VS subsegment. Cấu trúc _HEAP_VS_SUBSEGMENT ở offset 0x00, trong khi các VS block bắt đầu ở offset 0x30:

![](pic/pic14.PNG)

**_HEAP_VS_CHUNK_HEADER Structure**

Busy VS blocks có 16-byte (0x10) header theo cấu trúc sau:
```
windbg> dt ntdll!_HEAP_VS_CHUNK_HEADER -r
   +0x000 Sizes : _HEAP_VS_CHUNK_HEADER_SIZE
      +0x000 MemoryCost : Pos 0, 16 Bits
      +0x000 UnsafeSize : Pos 16, 16 Bits
      +0x004 UnsafePrevSize : Pos 0, 16 Bits
      +0x004 Allocated : Pos 16, 8 Bits
      +0x000 KeyUShort : Uint2B
      +0x000 KeyULong : Uint4B
      +0x000 HeaderBits : Uint8B
   +0x008 EncodedSegmentPageOffset : Pos 0, 8 Bits
   +0x008 UnusedBytes : Pos 8, 1 Bit
   +0x008 SkipDuringWalk : Pos 9, 1 Bit
   +0x008 Spare : Pos 10, 22 Bits
   +0x008 AllocatedChunkBits : Uint4B
```
   - Sizes - Cấu trúc con có kích thước QWORD được mã hóa, nó chứa thông tin quan trọng về kích thước và trạng thái
      - MemoryCost - Được dùng cho free VS blocks. Một giá trị được tính dựa trên độ lớn của phần được commit của block. Phần block được commit càng lớn thì có chi phí bộ nhớ càng thấp. Điều này có nghĩa là nếu một block có chi phí bộ nhớ thấp được chọn để cấp phát, thì lượng bộ nhớ nhỏ hơn cần được cam kết. 
      - UnsafeSize - Size của the VS block (bao gồm block header) in 16-byte blocks.
      - UnsafePrevSize - Size của the previous VS block (includes the block header) in 16-byte blocks.
      - Allocated - Block is busy nếu giá trị này khác 0.
      - KeyULong - Được sử dụng trong free VS blocks. Một key có kích thước DWORD được sử dụng khi chèn free VS block và VS free tree. High WORD là trường UnsafeSize và low WORD là trường MemoryCost.
   - EncodedSegmentPageOffset – Offset được mã hóa của block bắt đầu của VS subsegment trong pages.
   - UnusedBytes - Flag cho biết liệu block có các byte không được sử dụng hay không, nghĩa là UserSize và tổng kích thước block (trừ 0x10 byte header) là khác nhau hay không. Nếu flag này được set, hai byte cuối cùng của VS block được coi là giá trị 16 bit low endian. Nếu số unused bytes là 1, high bit của giá trị 16 bit này được set và các bit còn lại không được sử dụng, ngược lại, high bit sẽ được clear và 13 bit thấp được sử dụng để lưu trữ giá trị byte chưa sử dụng.
   
Hình bên dưới minh họa một busy VS block (lưu ý rằng 9 byte đầu tiên đã được encode):

![](pic/pic15.PNG)

**_HEAP_VS_CHUNK_FREE_HEADER Structure**

Các Free VS block có header 32 byte (0x20) trong đó 8 byte đầu tiên là 8 byte đầu tiên của cấu trúc _HEAP_VS_CHUNK_HEADER. Bắt đầu từ offset 0x08 là trường Node hoạt động như một note trong VS free tree (VsContext.FreeChunkTree):

```
windbg> dt ntdll!_HEAP_VS_CHUNK_FREE_HEADER -r
+0x000 Header : _HEAP_VS_CHUNK_HEADER
   +0x000 Sizes : _HEAP_VS_CHUNK_HEADER_SIZE
      +0x000 MemoryCost : Pos 0, 16 Bits
      +0x000 UnsafeSize : Pos 16, 16 Bits
      +0x004 UnsafePrevSize : Pos 0, 16 Bits
      +0x004 Allocated : Pos 16, 8 Bits
      +0x000 KeyUShort : Uint2B
      +0x000 KeyULong : Uint4B
      +0x000 HeaderBits : Uint8B
   +0x008 EncodedSegmentPageOffset : Pos 0, 8 Bits
   +0x008 UnusedBytes : Pos 8, 1 Bit
   +0x008 SkipDuringWalk : Pos 9, 1 Bit
   +0x008 Spare : Pos 10, 22 Bits
   +0x008 AllocatedChunkBits : Uint4B
+0x000 OverlapsHeader : Uint8B
+0x008 Node : _RTL_BALANCED_NODE
```

Hình bên dưới minh họa một free VS block (lưu ý rằng 8 byte đầu tiên đã được encode):

![](pic/pic16.PNG)

**VS Free Tree**
Cấp phát và giải phóng VS sử dụng VS free tree để tìm kiếm và lưu trữ thông tin về các free VS block. 

Root của VS free tree được lưu trữ trong VsContext.FreeChunkTree và các node trên cây là trường Node của các free VS block. Key được sử dụng để chèn các node vào trong VS free tree là trường Header.Sizes.KeyULong của free VS block (Sizes.KeyULong đã được thảo luận trong phần phụ “_HEAP_VS_CHUNK_HEADER Structure” ở trên).

Below is an illustration of a VS free tree in which there are three free VS blocks with sizes 0xF80, 0x1010 and 0x3010 (all portions of the free blocks are committed - MemoryCost is 0x0000):

Dưới đây là hình minh họa về một VS free tree, trong đó có ba free VS blocks với kích thước 0xF80, 0x1010 và 0x3010 (tất cả các phần của free block đều được commit - MemoryCost là 0x0000):

![](pic/pic17.PNG)

**VS Allocation**

VS allocation được thực hiện thông qua hàm RtlpHpVsContextAllocate(), với các đối số như sau:
```
PVOID RtlpHpVsContextAllocate(_HEAP_VS_CONTEXT* VsContext, SIZE_T UserSize, SIZE_T AllocSize, ULONG Flags)
```

Sơ đồ bên dưới mô tả logic của hàm RtlpHpVsContextAllocate():

![](pic/pic18.PNG)

Trước tiên, RtlpHpVsContextAllocate() duyệt VS free tree để tìm một free VS block có thể phù hợp với phân bổ. Key tìm kiếm được sử dụng để tìm free VS block là một giá trị có kích thước DWORD trong đó high WORD là số block 16 byte có thể chứa AllocSize cộng một (đối với block header) và low WORD là 0 (đối với MemoryCost). Điều này có nghĩa là một tìm kiếm phù hợp nhất được thực hiện với free VS block với chi phí bộ nhớ thấp nhất (hầu hết các phần của block được commit) được ưu tiên, nói cách khác, nếu hai hoặc nhiều free block có kích thước tương đương phù hợp nhất với phân bổ, khối miễn phí được commit nhiều nhất sẽ được chọn để phân bổ. Nếu không có bất kỳ free VS block nào phù hợp với phân bổ, một VS segment mới sẽ được tạo.

Vì kích thước của free VS block đã chọn có thể lớn hơn kích thước block có thể chứa AllocSize, các free VS block lớn sẽ được tách ra trừ khi kích thước block của block còn lại sẽ nhỏ hơn 0x20 byte (kích thước của free VS block header), block còn lại sau khi tách ra phải lớn hơn 0x20 bytes thì mới được tách.

![](pic/pic19.PNG)

Việc tách free VS block được thực hiện bởi hàm RtlpHpVsChunkSplit(). RtlpHpVsChunkSplit() cũng là hàm loại bỏ free VS block khỏi VS free tree và cũng chèn free block còn lại kết quả vào VS free tree nếu có thể tách block.

**VS Freeing**

VS Freeing được thực hiện thông qua hàm RtlpHpVsContextFree(), nó có các đối số sau:
```
BOOLEAN RtlpHpVsContextFree(_HEAP_VS_CONTEXT* VsContext, _HEAP_VS_SUBSEGMENT* VsSubegment, PVOID UserAddress, ULONG Flags, ULONG* LfhBlockSize)
```

Trong đó UserAddress là địa chỉ của VS block được giải phóng và LfhBlockSize sẽ trở thành block size của VS block được giải phóng trừ đi 0x10 (kích thước busy VS block header). LfhBlockSize sẽ được dùng bởi việc gọi hàm RtlpHpVsContextFree() sử dụng trong việc cập nhật bộ đếm LFH bucket usage tương ứng với LfhBlockSize.

Trước tiên, RtlpHpVsContextFree() kiểm tra xem VS block có thực sự được cấp phát hay không bằng cách kiểm tra trường Allocated trong header của block đó. Sau đó, nó sẽ gọi RtlpHpVsChunkCoalesce() để liên kết block được giải phóng với các free block lân cận (trước và sau)

![](pic/pic20.PNG)

Cuối cùng, free block is được liên kết được chèn vào VS free tree để dùng cho việc phân bổ.

### 2.4. LOW FRAGMENTATION HEAP
Low Fragmentation Heap (LFH) được sử dụng để phân bổ block có kích thước từ 1 đến 16.368 (0x3FF0) byte. Tương tự như LFH trong NT Heap, LFH trong Segment Heap ngăn chặn sự phân mảnh bằng cách sử dụng lược đồ bucketing khiến các block có kích thước tương tự được cấp phát từ các block có bộ nhớ pre-allocated lớn hơn.

Dưới đây là bảng liệt kê các LFH bucket khác nhau, kích thước phân bổ (allocation sizes) được phân phối cho các bucket và mức độ chi tiết (granularity) tương ứng của các bucket:

| Bucket       | Allocation Size                         | Granularity  |
|:------------:|----------------------------------------:|-------------:|
| 1 – 64       | 1 – 1,024 bytes (0x1 – 0x400)           | 16 bytes     |
| 65 – 80      | 1,025 – 2,048 bytes (0x401 – 0x800)     | 64 bytes     |
| 81 – 96      | 2,049 – 4,096 bytes (0x801 – 0x1000)    | 128 bytes    |
| 97 – 112     | 4,097 – 8,192 bytes (0x1001 – 0x2000)   | 256 bytes    |
| 113 – 128    | 8,193 – 16,368 bytes (0x2001 – 0x3FF0)  | 512 bytes    |

Các LFH bucket chỉ được kích hoạt (enabled) nếu kích thước phân bổ tương ứng của nó được phát hiện là phổ biến. LFH bucket activation và usage counter sẽ được thảo luận kỹ hơn ở phần sau.

Dưới đây là hình minh họa một số bucket đã kích hoạt và một số bucket không được kích hoạt bao gồm kích thước phân bổ tương ứng của chúng:

![](pic/pic21.PNG)

Các bucket #1, #65 và #97 được kích hoạt và do đó, các yêu cầu phân bổ cho các kích thước phân bổ tương ứng sẽ được phục vụ thông qua các LFH bucket này. Các bucket #81 và #113 vẫn chưa được kích hoạt và do đó, các yêu cầu phân bổ cho các kích thước phân bổ tương ứng sẽ khiến usage counter của các LFH bucket này được cập nhật. Nếu usage counter đạt đến một giá trị cụ thể sau khi cập nhật, bucket của nó sẽ được kích hoạt và phân bổ sẽ được phục vụ qua LFH bucket, ngược lại, yêu cầu cấp phát cuối cùng sẽ được chuyển đến VS allocation component.

**LFH Subsegments**

LFH component dựa vào backend để tạo các LFH subsegment nơi các LFH block được cấp phát từ đó. Một LFH subsegment là một loại đặc biệt của backend block trong đó trường RangeFlags của “first” page range descriptor tương ứng có PAGE_RANGE_FLAGS_LFH_SUBSEGMENT (0x01) bit set.

Dưới đây là minh họa về mối quan hệ của HeapBase, một segment và một LFH subsegment:

![](pic/pic22.PNG)

**_HEAP_LFH_CONTEXT Structure**

LFH context theo dõi các LFH bucket, LFH bucket usage counters và các thông tin khác liên quan đến trạng thái LFH. Nó được lưu trữ trong trường LfhContext trong HeapBase và có các trường sau:
```
windbg> dt ntdll!_HEAP_LFH_CONTEXT -r
   +0x000 BackendCtx : Ptr64 Void
   +0x008 Callbacks : _HEAP_SUBALLOCATOR_CALLBACKS
   +0x030 SubsegmentCreationLock : _RTL_SRWLOCK
   +0x038 MaxAffinity : UChar
   +0x040 AffinityModArray : Ptr64 UChar
   +0x050 SubsegmentCache : _HEAP_LFH_SUBSEGMENT_CACHE
      +0x000 SLists : [7] _SLIST_HEADER
   +0x0c0 Buckets : [129] Ptr64 _HEAP_LFH_BUCKET
```
   - BackendCtx - trỏ đến cấu trúc _SEGMENT_HEAP (HeapBase).
   - Callbacks – Các callback được mã hóa (xem thêm ở phần 3.5) để quản lý các phần mở rộng LFH subsegments và LFH context.
   - MaxAffinity - Số lượng tối đa slot giống nhau có thể được tạo.
   - SubsegmentCache - Tracks cached (unused) LFH subsegments.
   - Buckets - Mảng các con trỏ trỏ đến các LFH bucket. Nếu một bucket được kích hoạt, bit 0 của con trỏ này sẽ clear và nó sẽ trỏ đến cấu trúc _HEAP_LFH_BUCKET. Mặt khác (nếu bit 0 được set), con trỏ trỏ đến cấu trúc _HEAP_LFH_ONDEMAND_POINTER được sử dụng để theo dõi việc sử dụng LFH bucket.

Reserved virtual memory nằm sau cấu trúc _SEGMENT_HEAP trong HeapBase, được gọi là phần mở rộng LFH context, được dynamically committed để lưu trữ bổ sung các cấu trúc liên quan đến LFH bucket cho các LFH bucket được kích hoạt động (xem hình minh họa ở trên).

**_HEAP_LFH_ONDEMAND_POINTER Structure**

Như đã đề cập ở trên, nếu LFH bucket không được kích hoạt, entry của bucket trong LfhContext.Buckets sẽ là usage counter. Bucket usage counter sẽ có cấu trúc sau:
```
windbg> dt ntdll!_HEAP_LFH_ONDEMAND_POINTER
   +0x000 Invalid : Pos 0, 1 Bit
   +0x000 AllocationInProgress : Pos 1, 1 Bit
   +0x000 Spare0 : Pos 2, 14 Bits
   +0x002 UsageData : Uint2B
   +0x000 AllBits : Ptr64 Void
```
   - Invalid - Điểm đánh dấu để xác định xem con trỏ này có phải là con trỏ _HEAP_LFH_BUCKET không hợp lệ (lowest bit set) hay không, từ đó xác định cấu trúc này là một bucket usage counter.
   - UsageData – Giá trị này có kích thước WORD mô tả việc sử dụng LFH bucket. Giá trị được lưu từ bit 0 đến bit 4 là số lượng các cấp phát đang hoạt động cùng kích thước cấp phát của bucket, giá trị này được tăng lên khi cấp phát và giảm khi giải phóng. Giá trị được lưu trong bit 5 đến bit 15 là số lượng yêu cầu cấp phát có cùng kích thước cấp phát của bucket, nó được tăng lên khi cấp phát.
   
**_HEAP_LFH_BUCKET Structure**

![](pic/pic2.PNG)
![](pic/pic2.PNG)
![](pic/pic2.PNG)
![](pic/pic2.PNG)
![](pic/pic2.PNG)
![](pic/pic2.PNG)


