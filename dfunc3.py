#!/usr/bin/python3
import argparse
import requests
import json
import sys

def parse_headers(header_list):
    headers = {}
    for h in header_list:
        if ":" not in h:
            continue
        key, value = h.split(":", 1)
        headers[key.strip()] = value.strip()
    return headers

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", help="PHPinfo URL: eg. https://example.com/phpinfo.php")
    parser.add_argument("--file", help="PHPinfo localfile path: eg. dir/phpinfo")
    parser.add_argument("--header", action="append", help='Custom HTTP header, e.g. --header "User-Agent: custom"')

    args = parser.parse_args()

    headers = parse_headers(args.header) if args.header else {}

    if args.url:
        try:
            phpinfo = requests.get(args.url, headers=headers, timeout=10).text
        except Exception as e:
            print(json.dumps({"error": f"Failed to fetch URL: {e}"}))
            sys.exit(1)

    elif args.file:
        try:
            with open(args.file, 'r', encoding="utf-8", errors="ignore") as f:
                phpinfo = f.read()
        except Exception as e:
            print(json.dumps({"error": f"Failed to read file: {e}"}))
            sys.exit(1)
    else:
        parser.print_help()
        sys.exit(1)

    try:
        inp = phpinfo.split('disable_functions</td><td class="v">')[1].split("</")[0].split(',')[:-1]
    except IndexError:
        print(json.dumps({"error": "Could not parse disable_functions from phpinfo output"}))
        sys.exit(1)

    dangerous_functions = [
        'pcntl_alarm','pcntl_fork','pcntl_waitpid','pcntl_wait','pcntl_wifexited',
        'pcntl_wifstopped','pcntl_wifsignaled','pcntl_wifcontinued','pcntl_wexitstatus',
        'pcntl_wtermsig','pcntl_wstopsig','pcntl_signal','pcntl_signal_get_handler',
        'pcntl_signal_dispatch','pcntl_get_last_error','pcntl_strerror','pcntl_sigprocmask',
        'pcntl_sigwaitinfo','pcntl_sigtimedwait','pcntl_exec','pcntl_getpriority',
        'pcntl_setpriority','pcntl_async_signals','error_log','system','exec','shell_exec',
        'popen','proc_open','passthru','link','symlink','syslog','ld','mail'
    ]

    modules = []
    if "mbstring.ini" in phpinfo:
        modules.append('mbstring')
        dangerous_functions += ['mb_send_mail']

    if "imap.ini" in phpinfo:
        modules.append('imap')
        dangerous_functions += ['imap_open','imap_mail']

    if "libvirt-php.ini" in phpinfo:
        modules.append('libvert')
        dangerous_functions += ['libvirt_connect']

    if "gnupg.ini" in phpinfo:
        modules.append('gnupg')
        dangerous_functions += ['gnupg_init']

    if "imagick.ini" in phpinfo:
        modules.append('imagick')

    exploitable_functions = [i for i in dangerous_functions if i not in inp]

    result = {
        "modules_detected": modules,
        "disabled_functions": inp,
        "exploitable_functions": exploitable_functions
    }

    print(json.dumps(result, indent=4))

if __name__ == "__main__":
    main()

