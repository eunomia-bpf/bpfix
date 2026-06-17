# ringbuf_branch_cookie_001

This case combines packet branch semantics with ringbuf helper protocol and
pointer provenance. The program reserves a ringbuf record, writes a branch
dependent mark, then destroys the ringbuf pointer through integer inline
assembly before submit.

The oracle requires the repaired program to keep reserve/submit behavior. The
verifier trace must show that the UDP `mark = 7` branch reaches the ringbuf
reserve block and that the TCP `mark = 11` path writes the submitted record;
the real packet tests check the branch return values.
