# Generate CA
cfssl genkey -initca ca_csr.json | cfssljson -bare ca
# Get generate redoctober cert
cfssl gencert -ca ca.pem -ca-key ca-key.pem -config ca_signing_config.json redoctober_csr.json | cfssljson -bare redoctober

rm *.csr
