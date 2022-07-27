#!/usr/bin/env python3
"""
This script is for parsing ETH wallet addresses from
Reddit comments and Tweets for delivery of NFT's
"""

import sys
import re
import argparse
import praw
from TwitterAPI import TwitterAPI, TwitterRequestError, TwitterConnectionError, TwitterPager

try:
    from keys import *
except:
    print("[!] Create a keys.py file with the required API "
          "keys in the same directory as the script!")
    raise SystemExit(0)


__version__ = '0.0.3'
__author__ = 'Corey Forman - @digitalsleuth'
__date__ = '27 JUL 2022'

raw_wallet_regex = re.compile("0x.{40}")
ens_wallet_regex = re.compile("\w+\.?\w+\.eth")


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
        for child in self.children:
            conv_id.append(self.data['id'])
            child_id.append(child.data['id'])
            text.append(child.data['text'])
        #return conv_id, child_id, text
        return text

def parse_reddit_comments(url, subreddit, output):
    """Reads through all comments and grabs wallet addresses"""
    try:
        if '' in {r_client_id, r_client_secret}:
            print("[!] One of your API values is missing! "
                  "Please check your keys.py file and try again.")
            raise SystemExit(2)
    except:
        pass
    addresses = []
    post_comments = []
    u_agent = "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0"
    post = f'https://www.reddit.com/r/{subreddit}/comments/{url}'
    reddit_ro = praw.Reddit(client_id=r_client_id,
                            client_secret=r_client_secret,
                            user_agent=u_agent)
    submission = reddit_ro.submission(url=post)
    submission.comments.replace_more(limit=None)
    for comment in submission.comments.list():
        post_comments.append(comment.body)

    for comment in post_comments:
        raw = re.search(raw_wallet_regex, comment)
        ens = re.search(ens_wallet_regex, comment)
        if raw and not ens:
            addresses.append((raw.group()).lower())
        elif ens and not raw:
            addresses.append((ens.group()).lower())
        elif ens and raw:
            addresses.append((ens.group()).lower())

    de_dup = sorted(set(addresses))
    with open(output, 'w') as output_file:
        for each_address in de_dup:
            output_file.write(f'{each_address}\n')
    output_file.close()

def parse_tweet_comments(msgid, output):
    """
    Reads through all replies to the given Tweet
    and grabs wallet addresses
    """
    try:
        if '' in {t_api_key, t_api_key_secret, t_access_token, t_access_token_secret}:
            print("[!] One of your API values is missing! "
                  "Please check your keys.py file and try again.")
            raise SystemExit(2)
    except:
        pass
    try:
        replies = []
        twapi = TwitterAPI(t_api_key,
                           t_api_key_secret,
                           t_access_token,
                           t_access_token_secret,
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
        addresses = []
        for each_item in pager.get_iterator(wait=1):
            node = TreeNode(each_item)
            orphans = [orphan for orphan in orphans if not node.find_parent_of(orphan)]
            if not root.find_parent_of(node):
                orphans.append(node)

        replies = root.list_l1()

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
    with open(output, 'w') as output_file:
        for each_address in de_dup:
            output_file.write(f'{each_address}\n')
    output_file.close()


def main():
    """Parse all passed arguments"""
    arg_parse = argparse.ArgumentParser(description=f"Python 3 Reddit Wallet Address parser"
                                                    f" v{__version__}")
    arg_parse.add_argument('-s', '--subreddit', help='subreddit to parse')
    arg_parse.add_argument('-t', '--tweet', help='tweet 19-digit ID')
    arg_parse.add_argument('-u', '--url', help='short URL for the reddit thread')
    arg_parse.add_argument('-o', '--output', help='choice in output file', required=True)
    arg_parse.add_argument('-v', '--version', action='version', version=arg_parse.description)

    if len(sys.argv[1:]) == 0:
        arg_parse.print_help()
        arg_parse.exit()

    args = arg_parse.parse_args()
    if args.subreddit:
        parse_reddit_comments(args.url, args.subreddit, args.output)
    elif args.subreddit and not args.url:
        print("Parsing Reddit Thread requires the short URL for the thread")
        raise SystemExit(0)
    elif args.tweet:
        parse_tweet_comments(args.tweet, args.output)
    elif (len(sys.argv[1:]) > 0) and not (args.subreddit or args.tweet):
        print("Please choose a valid option.")
        raise SystemExit(0)

if __name__ == '__main__':
    main()
