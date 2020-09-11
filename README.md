# WINDOWS 10 SEGMENT HEAP INTERNALS
-

# ABSTRACT
Được ra mắt trong Windows 10, Segment Heap triển khai native heap được sử dụng trong các ứng dụng Windows (trước đây được gọi là Modern/Metro apps) và các quy trình hệ thống nhất định. Việc triển khai heap mới này là một sự bổ sung được nghiên cứu kỹ lưỡng và được tài liệu hóa rộng rãi để NT Heap vẫn được sử dụng trong các ứng dụng truyền thống và trong các loại phân bổ nhất định trong các ứng dụng Windows.

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
