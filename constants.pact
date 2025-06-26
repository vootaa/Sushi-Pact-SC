(module constants GOVERNANCE
  (defcap GOVERNANCE:bool () (enforce-guard ADMIN_GUARD))

  (defconst ADMIN_KEYSET (+ (read-msg "ns") ".admin-keyset"))
  (defconst ADMIN_GUARD (keyset-ref-guard ADMIN_KEYSET))
)