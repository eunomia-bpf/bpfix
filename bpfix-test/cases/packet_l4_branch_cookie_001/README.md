# packet_l4_branch_cookie_001

Branch-merge packet parser case. UDP and TCP branches establish different
checked L4 pointers, then the program merges and loses verifier pointer
provenance through an integer cookie. The oracle checks both branch semantics.
