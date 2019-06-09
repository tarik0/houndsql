#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from time import sleep
from os import _exit
from datetime import datetime
from threading import Thread
from colorama import init
from colorama import Fore, Back, Style
from re import findall
from sys import argv
from bs4 import BeautifulSoup
from requests import get, exceptions

search_url = "https://www.google.com/search?client=firefox-b-d&q="
error_text = "mysql_fetch_array(): supplied argument is not a valid MySQL result resource in"

vuln_sites = []
scan_finished = False

def print_error(*args , **kwargs):
    current_dt = datetime.now()
    time_str = current_dt.strftime(Fore.CYAN + "[%H:%M:%S] " + Style.RESET_ALL)
    print(time_str + Fore.RED + "[-]" + Style.RESET_ALL, *args, **kwargs)

def print_success(*args , **kwargs):
    current_dt = datetime.now()
    time_str = current_dt.strftime(Fore.CYAN + "[%H:%M:%S] " + Style.RESET_ALL)
    print(time_str + Fore.GREEN + "[+]" + Style.RESET_ALL, *args, **kwargs)

def print_site(*args, **kwargs):
    current_dt = datetime.now()
    time_str = current_dt.strftime(Fore.CYAN + "[%H:%M:%S] " + Style.RESET_ALL)
    print(time_str + Fore.YELLOW + "->" + Style.RESET_ALL, *args, **kwargs)

def print_status(*args, **kwargs):
    current_dt = datetime.now()
    time_str = current_dt.strftime(Fore.CYAN + "[%H:%M:%S] " + Style.RESET_ALL)
    print(time_str + Fore.YELLOW + "[*]" + Style.RESET_ALL, *args, **kwargs)

def print_question(*args, **kwargs):
    current_dt = datetime.now()
    time_str = current_dt.strftime(Fore.CYAN + "[%H:%M:%S] " + Style.RESET_ALL)
    print(time_str +Fore.BLUE + "[?]" + Style.RESET_ALL, *args, end="")
    return input(" ", **kwargs)

def print_banner():
    banner = """
 {}             .--~~,__{}
 {}:-....,-------`~~'._.'{}        {}Hound{}
 {} `-,,,  ,_      ;'~U'{}    {}==============={}
 {}  _,-' ,'`-__; '--.{}  {}SQL Injection Vulnerable{}
 {} (_/'~~      ''''(;{}       {}Site Finder{}
    """.format(
        Fore.BLUE, Style.RESET_ALL,
        Fore.BLUE, Style.RESET_ALL,
        Fore.YELLOW, Style.RESET_ALL,
        Fore.BLUE, Style.RESET_ALL,
        Fore.YELLOW, Style.RESET_ALL,
        Fore.BLUE, Style.RESET_ALL,
        Fore.YELLOW, Style.RESET_ALL,
        Fore.BLUE, Style.RESET_ALL,
        Fore.YELLOW, Style.RESET_ALL
        )
    print(banner)
    

def search_google(dork):
    response = get(search_url + dork, headers={
        "Host": "www.google.com",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:68.0) Gecko/20100101 Firefox/68.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US;q=0.5,en;q=0.3",
        "Accept-Encoding": "gzip, deflate",
        "DNT": "1",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Pragma": "no-cache",
        "Cache-Control": "no-cache",
        "TE": "Trailers"
    })

    shall_exit = False
    if (response.status_code != 200):
        print_error("Google bad response code:", response.status_code)
        shall_exit = True
    if ("Our systems have detected unusual traffic from your computer network." in response.text):
        print_error("Robot detection found! Need to fill Captcha!")
        shall_exit = True
    if (shall_exit):
        _exit(0)

    current_dt = datetime.now()
    output_file_name = current_dt.strftime("%Y_%m_%d-%H_%M_%S")
    with open("./google_search_results/response_" + output_file_name + ".html", "w+" ,  encoding='utf8') as f:
        f.write(response.text)
        f.close()
    
    source = BeautifulSoup(response.text, "lxml")
    found_links = []
    for link in source.find_all("a", href=True):
        links = findall('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', link["href"])
        if (len(links) == 0):
            continue
        if ("google" in link["href"]):
            continue
        found_links.append(link)
    return found_links

def try_sites(links):
    for link in links:
        try:
            response = get(link["href"] + "'", headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:68.0) Gecko/20100101 Firefox/68.0",
            })

            if (response.status_code == 200 and error_text in response.text):
                global vuln_sites
                vuln_sites.append(link["href"])
        except:
            continue

    global scan_finished
    scan_finished = True

def main():
    init()
    print_banner()
    dork = ""
    if (len(argv) < 2):
        print_status("No dork given as parameter! Asking one!")
        dork = print_question("Google dork to search:")
    else:
        dork = argv[1]

    print_status("Searching Google with this dork:", dork, end="\n\n")
    try:
        links = search_google(dork)
    except exceptions.ConnectionError:
        print_error("An connection error occurred while searching on google!")

    if (len(links) == 0):
        print_error("No URL found from search!")
        _exit(0)

    print_success(len(links), "Links has been found!")

    scanning = Thread(name='scanning', target=try_sites, args=(links,))

    scanning.start()
    tmp = 0
    animation = "|/-\\"

    while (scan_finished == False):
        char = animation[tmp % len(animation)]
        current_dt = datetime.now()
        time_str = current_dt.strftime(Fore.CYAN + "[%H:%M:%S] " + Style.RESET_ALL)
        print(time_str + Fore.BLUE + "[" + char + "]" + Style.RESET_ALL, "Scanning found links!", end="\r")
        sleep(0.1)
        tmp = tmp + 1

    scanning.join()

    if (len(vuln_sites) == 0):
        print_error("No vulnerable sites found! Try another dork!")
        _exit(0)

    print_success("Scanning finished!", len(vuln_sites), "Sites might be vulnerable!")
    
    current_dt = datetime.now()
    output_file_name = "vuln_" + current_dt.strftime("%Y_%m_%d-%H_%M_%S")
    print_success("Found sites are saved into", output_file_name + ".txt !", end="\n\n")

    with open("./scan_results/" + output_file_name + ".txt", "w+", encoding='utf8') as f:
        for site in vuln_sites:
            f.write(site + "\n")
        f.close()
    
    print_status("Listing found vulnerable sites!")
    for site in vuln_sites:
       print_site(site)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print_error("Ctrl+C, Exiting! See you soon!")
        sleep(1)
        _exit(0)