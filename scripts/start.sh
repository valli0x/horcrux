mkdir cosigner_1 cosigner_2 cosigner_3
./horcrux create-shares --ecdsa - 2 3
 		mv cmp_config_1.txt cosigner_1/cmp_config.txt
 		mv cmp_config_2.txt cosigner_2/cmp_config.txt
 		mv cmp_config_3.txt cosigner_3/cmp_config.txt
 		mv cmp_presig_1.txt cosigner_1/cmp_presig.txt
 		mv cmp_presig_2.txt cosigner_2/cmp_presig.txt
 		mv cmp_presig_3.txt cosigner_3/cmp_presig.txt
 		mv private_share_1.json cosigner_1/share.json
 		mv private_share_2.json cosigner_2/share.json
 		mv private_share_3.json cosigner_3/share.json

./horcrux config init --home cosigner_1 chain-1 "tcp://localhost:8181" -c -p "tcp://localhost:8192|2,tcp://localhost:8193|3" -l "tcp://localhost:8191" -t 2 --timeout 1500ms

./horcrux config init --home cosigner_2 chain-1 "tcp://localhost:8182" -c -p "tcp://localhost:8191|1,tcp://localhost:8193|3" -l "tcp://localhost:8192" -t 2 --timeout 1500ms

./horcrux config init --home cosigner_3 chain-1  "tcp://localhost:8183" -c -p "tcp://localhost:8191|1,tcp://localhost:8192|2" -l "tcp://localhost:8193" -t 2 --timeout 1500ms
