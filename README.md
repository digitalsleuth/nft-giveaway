# nft-giveaway
A script for parsing Reddit and Twitter for ETH addresses during an NFT Giveaway

## EXAMPLE USAGE

### NFT TRANSACTIONS

./nft-giveaway.py loopring --nft https://lexplorer.io/nfts/0x5eabe331801092f8432d13845729ee46405962a1-0-0x749b9777cc13fb474643313c6c5616433582bcec-0xedf5e8e44f0a3b7b59a1bd19869915b614093ee151b7c8a671783ed2324172ea-10 --account 62231 -o nft-test.csv -c keys.cfg

### NFT HOLDERS

./nft-giveaway.py loopring --nft https://lexplorer.io/nfts/0x5eabe331801092f8432d13845729ee46405962a1-0-0x749b9777cc13fb474643313c6c5616433582bcec-0xedf5e8e44f0a3b7b59a1bd19869915b614093ee151b7c8a671783ed2324172ea-10 -o nft-holders.txt -c keys.cfg

### NFT HOLDERS WITH QUANTITY HELD

./nft-giveaway.py loopring --nft https://lexplorer.io/nfts/0x5eabe331801092f8432d13845729ee46405962a1-0-0x749b9777cc13fb474643313c6c5616433582bcec-0xedf5e8e44f0a3b7b59a1bd19869915b614093ee151b7c8a671783ed2324172ea-10 -o nft-holders-amounts.csv -c keys.cfg -q

### REDDIT THREAD PARSING

./nft-giveaway.py reddit -s SuperStonk -u w799hr -c keys.cfg -o reddit-giveaway.txt

### TWITTER TWEET PARSING - USER NAMES

./nft-giveaway.py twitter -c keys.cfg -o twitter-names.txt -t 1566898328197103618 -n

### TWITTER TWEET PARSING - WALLET ADDRESSES

./nft-giveaway.py twitter -c keys.cfg -o twitter-wallets.txt -t 1566898328197103618 -w
