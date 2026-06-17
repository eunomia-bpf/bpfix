# ringbuf_nested_missing_null_001

The program reserves an audit record and then reserves a second event record.
It checks the audit record but writes to the second reserve result without a
null check, while the first reference is still live.

This is a composed nullable-helper/reference cleanup case. A correct repair
must check the second reserve result, release the first record on failure, and
preserve the normal path that submits two distinct records.
