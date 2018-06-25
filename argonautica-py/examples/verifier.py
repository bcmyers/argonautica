from argonautica import Verifier

verifier = Verifier(secret_key='somesecret')
is_valid = verifier.verify(
    hash='$argon2id$v=19$m=4096,t=192,p=4$n7F2qAECNLz7En4d9MsC6HIPWKiFZ5BHopIvoF1CBPs$Uk+pYp97ySGgal1OcrKfcA',
    password='P@ssw0rd',
)
assert(is_valid)
