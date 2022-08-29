#!/usr/bin/env python3
"""
This script is for parsing ETH wallet addresses from
Reddit comments and Tweets for delivery of NFT's

Additionally, it can be used to query the holders of
a specific NFT, identified by the URL from a Loopring
Explorer page displaying the NFT.
"""

import os
import sys
import re
import argparse
import configparser
import requests
import json
from datetime import datetime as dt
import praw
from TwitterAPI import TwitterAPI, TwitterRequestError, TwitterConnectionError, TwitterPager


__version__ = '1.1.0'
__author__ = 'Corey Forman - @digitalsleuth'
__date__ = '29 AUG 2022'

raw_wallet_regex = re.compile("0x.{40}")
ens_wallet_regex = re.compile("\w+\.?\w+\.eth")

class LoopringApi:
    """Enpoints for Api queries"""
    MAINNET = "https://api3.loopring.io"
    TESTNET_UAT2 = "https://uat2.loopring.io"
    TESTNET_UAT3 = "https://uat3.loopring.io"

    """Query paths for Apis"""
    ACCOUNT = 'https://api3.loopring.io/api/v3/account'
    NFT_DATA = f"{MAINNET}/api/v3/nft/info/nftData"
    NFT_HOLDERS = f"{MAINNET}/api/v3/nft/info/nftHolders"
    NFT_NFTS = f"{MAINNET}/api/v3/nft/info/nfts"
    USER_NFT_BALANCES = f"{MAINNET}/api/v3/user/nft/balances"


class TreeNode:
    """Extracts required values from returned data object"""
    def __init__(self, data):
        """data is a tweet's json object"""
        self.data = data
        self.children = []

    def id(self):
        """a node is identified by its author"""
        return self.data['author_id']

    def reply_to(self):
        """the reply-to user is the parent of the node"""
        return self.data['in_reply_to_user_id']

    def find_parent_of(self, node):
        """append a node to the children of it's reply-to user"""
        if node.reply_to() == self.id():
            self.children.append(node)
            return True
        for child in self.children:
            if child.find_parent_of(node):
                return True
        return False

    def print_tree(self, level):
        """level 0 is the root node, then incremented for subsequent generations"""
        level += 1
        for child in self.children:
            child.print_tree(level)

    def list_l1(self):
        """Returns a list of reply data"""
        conv_id = []
        child_id = []
        text = []
        author_id = []
        for child in self.children:
            conv_id.append(self.data['id'])
            child_id.append(child.data['id'])
            text.append(child.data['text'])
            author_id.append(child.data['author_id'])
        return conv_id, child_id, text, author_id


def parse_ids_from_url(nft_url):
    """Parse an NFT Url for required ID data"""
    ids = nft_url.rstrip('/').rsplit('/', 1)[-1]
    id_list = ids.split('-')

    for section in id_list:
        if len(str(section)) < 5:
            id_list.remove(section)

    minter_id, token_address, nft_id = id_list
    return minter_id, token_address, nft_id

def query_nft_data(minter_id, token_address, nft_id, config):
    """Used to query the NFT Data hash"""
    load_config = configparser.ConfigParser()
    load_config.read(config)
    API_KEY = load_config['LOOPRING']['api_key']
    HEADERS = {'X-API-KEY': API_KEY}
    payload = {'minter': minter_id, 'tokenAddress': token_address, 'nftId': nft_id}
    api_request = requests.get(LoopringApi.NFT_DATA, params=payload, headers=HEADERS)
    api_response = json.loads(api_request.text)
    nft_data = api_response["nftData"]

    return nft_data

def query_nft_holders(nft_data, config):
    """Returns a json-formatted output of holders of the identified NFT"""
    load_config = configparser.ConfigParser()
    load_config.read(config)
    API_KEY = load_config['LOOPRING']['api_key']
    API_LIMIT = load_config['LOOPRING']['api_limit']
    payload = {'nftData': nft_data, 'limit': API_LIMIT}
    HEADERS = {'X-API-KEY': API_KEY}
    api_request = requests.get(LoopringApi.NFT_HOLDERS, params=payload, headers=HEADERS)
    api_response = json.loads(api_request.text)

    num_holders = api_response['totalNum']
    nft_holders = api_response['nftHolders']
    for holder in nft_holders:
        holder_payload = {'accountId': holder['accountId']}
        account_request = requests.get(LoopringApi.ACCOUNT, params=holder_payload)
        account_response = json.loads(account_request.text)
        holder['wallet'] = account_response['owner'].lower()

    return nft_holders, num_holders

def parse_nft_holders(args):
    """Runs functions necessary for grabbing holder data and outputs parsed data"""
    print("[-] Parsing the ID values from the URL")
    minter_id, token_address, nft_id = parse_ids_from_url(args['nft'])
    print("[-] Getting the NftData hash from the API")
    nft_data = query_nft_data(minter_id, token_address, nft_id, args['config'])
    print("[-] Compiling and parsing a list of the NFT holders")
    nft_holders, num_holders = query_nft_holders(nft_data, args['config'])
    sorted_nft_holders = sorted(nft_holders, key=lambda amount: int(amount['amount']), reverse=True)

    out_file = args['output']
    if os.path.exists(out_file):
        response = input(f'[WARNING] {out_file} already exists - overwrite? [Y/n] ')
        while response not in ['Y', 'N', 'y', 'n', '']:
            response = input(f'[WARNING] {output} already exists - overwrite? [Y/n] ')
        if response in ['Y', 'y', '']:
            print(f"[+] Data will be output to {out_file}")
            with open(out_file, 'w') as output_file:
                output_file.write(f'Total Holder Count: {num_holders}\n')
                for holder in sorted_nft_holders:
                    if args['amount']:
                        output = f'{holder["wallet"]}, {holder["amount"]}'
                    else:
                        output = f'{holder["wallet"]}'
                    output_file.write(f'{output}\n')
            output_file.close()

        elif response in ['N', 'n']:
            out_file = f'{out_file}_{int(dt.timestamp(dt.now()))}'
            print(f"[+] Data will be output to {out_file}")
            with open(out_file, 'w') as output_file:
                output_file.write(f'Total Holder Count: {num_holders}\n')
                for holder in sorted_nft_holders:
                    if args['amount']:
                        output = f'{holder["wallet"]}, {holder["amount"]}'
                    else:
                        output = f'{holder["wallet"]}'
                    output_file.write(f'{output}\n')
            output_file.close()

    else:
        with open(out_file, 'a') as output_file:
            print(f"[+] Data will be appended to {out_file}")
            output_file.write(f'Total Holder Count: {num_holders}\n')
            for holder in sorted_nft_holders:
                if args['amount']:
                    output = f'{holder["wallet"]}, {holder["amount"]}'
                else:
                    output = f'{holder["wallet"]}'
                output_file.write(f'{output}\n')
        output_file.close()
    print("[+] Output complete")

def parse_reddit_comments(url, subreddit, output, config):
    """Reads through all comments and grabs wallet addresses"""
    post_comments = []
    load_config = configparser.ConfigParser()
    load_config.read(config)
    client_id = load_config['REDDIT']['client_id']
    client_secret = load_config['REDDIT']['client_secret']
    u_agent = load_config['GENERAL']['u_agent']
    try:
        if '' in {client_id, client_secret, u_agent}:
            print("[!] One of your API values is missing! "
                  "Please check your config file and try again.")
            raise SystemExit(2)
    except:
        pass
    post = f'https://www.reddit.com/r/{subreddit}/comments/{url}'
    reddit_ro = praw.Reddit(client_id=client_id,
                            client_secret=client_secret,
                            user_agent=u_agent)
    submission = reddit_ro.submission(url=post)
    submission.comments.replace_more(limit=None)
    for comment in submission.comments.list():
        post_comments.append(comment.body)

    de_dup = grab_wallets(post_comments)

    with open(output, 'w') as output_file:
        for each_line in de_dup:
            output_file.write(f'{each_line}\n')
    output_file.close()

def parse_tweet_comments(msgid, output, grab_wallet, grab_name, config):
    """Reads through all replies to the given Tweet and grabs wallet addresses"""
    load_config = configparser.ConfigParser()
    load_config.read(config)
    api_key = load_config['TWITTER']['api_key']
    api_key_secret = load_config['TWITTER']['api_key_secret']
    access_token = load_config['TWITTER']['access_token']
    access_token_secret = load_config['TWITTER']['access_token_secret']
    try:
        if '' in {api_key, api_key_secret, access_token, access_token_secret}:
            print("[!] One of your API values is missing! "
                  "Please check your config file and try again.")
            raise SystemExit(2)
    except:
        pass
    try:
        replies = []
        twapi = TwitterAPI(api_key,
                           api_key_secret,
                           access_token,
                           access_token_secret,
                           api_version='2')
        json_resp = twapi.request(f'tweets/:{msgid}', {'tweet.fields': 'conversation_id'}).json()
        convo_id = json_resp.get('data')['conversation_id']
        #  Following code block source:
        #  https://towardsdatascience.com/mining-replies-to-tweets-a-walkthrough-9a936602c4d6
        root_ent = twapi.request(f'tweets/:{convo_id}',
                                 {'tweet.fields': 'author_id,conversation_id,created_at,in_reply_to_user_id'
                                 })
        for entry in root_ent:
            root = TreeNode(entry)
        pager = TwitterPager(twapi, 'tweets/search/recent',
                             {'query': f'conversation_id:{convo_id}',
                              'tweet.fields': 'author_id,conversation_id,created_at,in_reply_to_user_id'
                             })
        orphans = []
        for each_item in pager.get_iterator(wait=1):
            node = TreeNode(each_item)
            orphans = [orphan for orphan in orphans if not node.find_parent_of(orphan)]
            if not root.find_parent_of(node):
                orphans.append(node)

        _, _, replies, author_ids = root.list_l1()

    except TwitterRequestError as exc_msg:
        print(f'[!] {exc_msg.status_code}')
        for err_msg in iter(exc_msg):
            print(f'[!]{err_msg}')
        raise SystemExit(2)

    except TwitterConnectionError as exc_msg:
        print(f'[!] {exc_msg}')
        raise SystemExit(2)

    except Exception as exc_msg:
        print(f'[!] {exc_msg}')
        raise SystemExit(2)

    if grab_wallet:
        de_dup = grab_wallets(replies)
    elif grab_name:
        de_dup = grab_names(author_ids, config)
    else:
        de_dup = grab_wallets(replies)

    if os.path.exists(output):
        response = input(f'[WARNING] {output} already exists - overwrite? [Y/n] ')
        while response not in ['Y', 'N', 'y', 'n', '']:
            response = input(f'[WARNING] {output} already exists - overwrite? [Y/n] ')
        if response in ['Y', 'y', '']:
            with open(output, 'w') as output_file:
                for each_line in de_dup:
                    output_file.write(f'{each_line}\n')
            output_file.close()
        elif response in ['N', 'n']:
            output = f'{output}_{int(dt.timestamp(dt.now()))}'
            with open(output, 'w') as output_file:
                for each_line in de_dup:
                    output_file.write(f'{each_line}\n')
            output_file.close()
    else:
        with open(output, 'a') as output_file:
            for each_line in de_dup:
                output_file.write(f'{each_line}\n')
        output_file.close()

def grab_wallets(replies):
    """Grabs Wallet Addresses from Replies"""
    addresses = []
    for reply in replies:
        raw = re.search(raw_wallet_regex, reply)
        ens = re.search(ens_wallet_regex, reply)
        if raw and not ens:
            addresses.append((raw.group()).lower())
        elif ens and not raw:
            addresses.append((ens.group()).lower())
        elif ens and raw:
            addresses.append((ens.group()).lower())
    de_dup = sorted(set(addresses))

    return de_dup

def grab_names(author_ids, config):
    """Resolves Usernames from Author IDs"""
    load_config = configparser.ConfigParser()
    load_config.read(config)
    api_key = load_config['TWITTER']['api_key']
    api_key_secret = load_config['TWITTER']['api_key_secret']
    access_token = load_config['TWITTER']['access_token']
    access_token_secret = load_config['TWITTER']['access_token_secret']
    usernames = []
    twapi = TwitterAPI(api_key, api_key_secret, access_token, access_token_secret, api_version='2')
    for auth_id in author_ids:
        name = twapi.request(f'users/:{auth_id}').json()['data']['username']
        usernames.append(name)
    de_dup = sorted(set(usernames))

    return de_dup

def main():
    """Parse all passed arguments"""
    arg_parse = argparse.ArgumentParser(description=f"Wallet Address Parser and NFT Query Tool"
                                                    f" v{__version__}")
    arg_parse.add_argument('-c', '--config', help='config file containing API keys', required=True)
    arg_parse.add_argument('-s', '--subreddit', help='subreddit to parse')
    arg_parse.add_argument('-t', '--tweet', help='tweet 19-digit ID')
    arg_parse.add_argument('-u', '--url', help='short URL for the reddit thread')
    arg_parse.add_argument('-n', '--name', help='grab usernames: Twitter Only', action='store_true')
    arg_parse.add_argument('-w', '--wallet', help='grab wallets: Twitter Only', action='store_true')
    arg_parse.add_argument('-o', '--output', help='choice in output file', required=True)
    arg_parse.add_argument('--nft', help='URL from lexplorer.io or explorer.loopring.io')
    arg_parse.add_argument('-a', '--amount', help='Used with --nft, show amounts of NFT\'s held', action='store_true')
    arg_parse.add_argument('-v', '--version', action='version', version=arg_parse.description)

    if len(sys.argv[1:]) == 0:
        arg_parse.print_help()
        arg_parse.exit()

    args = arg_parse.parse_args()
    all_args = vars(args)

    if not args.config:
        print("[!] Config file containing API keys is required!")
        raise SystemExit(0)
    if args.subreddit:
        parse_reddit_comments(args.url, args.subreddit, args.output, args.config)
    elif args.subreddit and not args.url:
        print("Parsing Reddit Thread requires the short URL for the thread")
        raise SystemExit(0)
    elif args.tweet:
        parse_tweet_comments(args.tweet, args.output, args.wallet, args.name, args.config)
    elif args.nft:
        parse_nft_holders(all_args)
    elif (len(sys.argv[1:]) > 0) and not (args.subreddit or args.tweet):
        print("Please choose a valid option.")
        raise SystemExit(0)

if __name__ == '__main__':
    main()
