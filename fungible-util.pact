(module fungible-util GOVERNANCE

    (defcap GOVERNANCE ()
      (enforce-guard constants.ADMIN_GUARD))
  
    (defun enforce-valid-amount
      ( precision:integer
        amount:decimal
      )
      (enforce (> amount 0.0) "Invalid amount: must be greater than 0")
      (enforce-precision precision amount)
    )
  
    (defun enforce-valid-account (account:string)
      (enforce (> (length account) 2) "Invalid account: must be at least 2 characters")
    )
  
    (defun enforce-precision
      ( precision:integer
        amount:decimal
      )
      (enforce
        (= (floor amount precision) amount)
        "precision violation")
    )
  
    (defun enforce-valid-transfer
      ( sender:string
        receiver:string
        precision:integer
        amount:decimal)
      (enforce (!= sender receiver)
        "sender cannot be the receiver of a transfer")
      (enforce-valid-amount precision amount)
      (enforce-valid-account sender)
      (enforce-valid-account receiver)
    )
  
  
    (defun check-reserved:string (account:string)
      " Checks ACCOUNT for reserved name and returns type if \
      \ found or empty string. Reserved names start with a \
      \ single char and colon, e.g. 'c:foo', which would return 'c' as type."
      (let ((pfx (take 2 account)))
        (if (= ":" (take -1 pfx)) (take 1 pfx) "")))
  
    (defun enforce-reserved:bool (account:string guard:guard)
      @doc "Enforce reserved account name protocols."
      (if (validate-principal guard account)
        true
        (let ((r (check-reserved account)))
          (if (= r "")
            true
            (if (= r "k")
              (enforce false "Single-key account protocol violation")
              (enforce false
                (format "Reserved protocol guard violation: {}" [r]))
              )))))
  
  )