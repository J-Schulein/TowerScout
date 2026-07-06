#!/usr/bin/env python3
import os
import sys
import json
import glob
import re
import urllib.request
import urllib.error


def build_body(artifacts_dir):
    repo = os.environ.get('GITHUB_REPOSITORY', '')
    workflow = os.environ.get('GITHUB_WORKFLOW', '')
    run_id = os.environ.get('GITHUB_RUN_ID', '')
    job = os.environ.get('GITHUB_JOB', '')
    sha = os.environ.get('GITHUB_SHA', '')

    lines = []
    lines.append(f"Repository: {repo}")
    lines.append(f"Workflow: {workflow}")
    lines.append(f"Run ID: {run_id}")
    lines.append(f"Job: {job}")
    lines.append(f"Commit: {sha}")
    lines.append("")

    pattern = os.path.join(artifacts_dir, '*')
    for path in sorted(glob.glob(pattern)):
        display = os.path.basename(path)
        lines.append(f"### {display}")
        try:
            with open(path, 'r', encoding='utf-8', errors='replace') as fh:
                content = fh.read(20000)
        except Exception as e:
            content = f"[error reading file: {e}]"
        lines.append('```')
        lines.append(content)
        lines.append('```')
        lines.append('')

    return '\n'.join(lines)


def create_issue(payload, token, repo):
    url = f"https://api.github.com/repos/{repo}/issues"
    data = json.dumps(payload).encode('utf-8')
    req = urllib.request.Request(url, data=data, headers={
        'Authorization': f'token {token}',
        'Accept': 'application/vnd.github.v3+json',
        'Content-Type': 'application/json'
    })
    try:
        with urllib.request.urlopen(req) as resp:
            body = resp.read().decode('utf-8')
            return json.loads(body)
    except urllib.error.HTTPError as e:
        try:
            detail = e.read().decode('utf-8')
        except Exception:
            detail = str(e)
        return {'error': str(e), 'detail': detail}
    except Exception as e:
        return {'error': str(e)}


def create_pr_comment(comment_body, token, repo, pr_number):
    url = f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments"
    data = json.dumps({'body': comment_body}).encode('utf-8')
    req = urllib.request.Request(url, data=data, headers={
        'Authorization': f'token {token}',
        'Accept': 'application/vnd.github.v3+json',
        'Content-Type': 'application/json'
    })
    try:
        with urllib.request.urlopen(req) as resp:
            body = resp.read().decode('utf-8')
            return json.loads(body)
    except urllib.error.HTTPError as e:
        try:
            detail = e.read().decode('utf-8')
        except Exception:
            detail = str(e)
        return {'error': str(e), 'detail': detail}
    except Exception as e:
        return {'error': str(e)}


def create_gist(body, token, repo):
    url = 'https://api.github.com/gists'
    payload = {
        'description': f'CI logs for {repo} run {os.environ.get("GITHUB_RUN_ID")}',
        'public': False,
        'files': {
            'ci-logs.txt': {'content': body}
        }
    }
    data = json.dumps(payload).encode('utf-8')
    req = urllib.request.Request(url, data=data, headers={
        'Authorization': f'token {token}',
        'Accept': 'application/vnd.github.v3+json',
        'Content-Type': 'application/json'
    })
    try:
        with urllib.request.urlopen(req) as resp:
            body = resp.read().decode('utf-8')
            return json.loads(body)
    except urllib.error.HTTPError as e:
        try:
            detail = e.read().decode('utf-8')
        except Exception:
            detail = str(e)
        return {'error': str(e), 'detail': detail}
    except Exception as e:
        return {'error': str(e)}


def write_actions_summary(body):
    summary_path = os.environ.get('GITHUB_STEP_SUMMARY')
    if summary_path:
        try:
            with open(summary_path, 'a', encoding='utf-8') as fh:
                fh.write('\n')
                fh.write(body)
            return True
        except Exception:
            return False
    return False


def find_pr_number():
    # Try GITHUB_REF like refs/pull/46/merge
    ref = os.environ.get('GITHUB_REF', '')
    m = re.match(r'^refs/pull/(\d+)/', ref)
    if m:
        return m.group(1)
    # Try event payload
    event_path = os.environ.get('GITHUB_EVENT_PATH')
    if event_path and os.path.exists(event_path):
        try:
            with open(event_path, 'r', encoding='utf-8') as fh:
                ev = json.load(fh)
            pr = ev.get('pull_request') or ev.get('issue')
            if isinstance(pr, dict) and 'number' in pr:
                return str(pr['number'])
        except Exception:
            pass
    return None


def main():
    artifacts_dir = sys.argv[1] if len(sys.argv) > 1 else 'test-artifacts'
    repo = os.environ.get('GITHUB_REPOSITORY')
    token = os.environ.get('GITHUB_TOKEN')

    body = build_body(artifacts_dir)
    payload = {'title': f"CI logs: {os.environ.get('GITHUB_WORKFLOW')} - run {os.environ.get('GITHUB_RUN_ID')}", 'body': body}

    out_resp = os.path.join(artifacts_dir, 'issue_response.json')
    out_url = os.path.join(artifacts_dir, 'issue_url.txt')

    if not token or not repo:
        print('GITHUB_TOKEN or GITHUB_REPOSITORY not set; skipping issue creation')
        with open(out_resp, 'w') as fh:
            json.dump({'skipped': True}, fh)
        open(out_url, 'w').write('')
        return 0

    result = create_issue(payload, token, repo)
    with open(out_resp, 'w') as fh:
        json.dump(result, fh)

    issue_url = result.get('html_url', '') if isinstance(result, dict) else ''
    with open(out_url, 'w') as fh:
        fh.write(issue_url)

    if issue_url:
        print('Created issue:', issue_url)
        return 0

    # Issue creation failed. Try fallbacks when Issues are disabled or creation failed.
    print('Issue creation response:', result)
    fallback_handled = False

    detail = result.get('detail', '') if isinstance(result, dict) else ''
    if isinstance(result, dict) and 'error' in result and 'Issues has been disabled' in detail:
        pr_num = find_pr_number()
        if pr_num:
            comment_resp = os.path.join(artifacts_dir, 'pr_comment_response.json')
            comment_url_file = os.path.join(artifacts_dir, 'pr_comment_url.txt')
            comment_result = create_pr_comment(body, token, repo, pr_num)
            with open(comment_resp, 'w') as fh:
                json.dump(comment_result, fh)
            comment_url = comment_result.get('html_url', '') if isinstance(comment_result, dict) else ''
            with open(comment_url_file, 'w') as fh:
                fh.write(comment_url)
            if comment_url:
                print('Created PR comment:', comment_url)
                fallback_handled = True
            else:
                print('PR comment attempt response:', comment_result)
        else:
            print('No PR number found; cannot post PR comment.')

    # Try writing to Actions summary if available
    try:
        summary_written = write_actions_summary(body)
        with open(os.path.join(artifacts_dir, 'actions_summary_written.txt'), 'w') as fh:
            json.dump({'written': bool(summary_written)}, fh)
        if summary_written:
            print('Wrote Actions summary (GITHUB_STEP_SUMMARY).')
            fallback_handled = True
    except Exception as e:
        print('Error writing Actions summary:', e)

    # Last resort: create a private gist with the logs
    if not fallback_handled:
        gist_resp = os.path.join(artifacts_dir, 'gist_response.json')
        gist_result = create_gist(body, token, repo)
        with open(gist_resp, 'w') as fh:
            json.dump(gist_result, fh)
        gist_url = gist_result.get('html_url', '') if isinstance(gist_result, dict) else ''
        if gist_url:
            print('Created gist:', gist_url)
            with open(out_url, 'w') as fh:
                fh.write(gist_url)
        else:
            print('Gist creation response:', gist_result)

    return 0


if __name__ == '__main__':
    sys.exit(main())
