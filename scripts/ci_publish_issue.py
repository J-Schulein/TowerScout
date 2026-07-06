#!/usr/bin/env python3
import os
import sys
import json
import glob
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
    else:
        print('Issue creation response:', result)

    return 0


if __name__ == '__main__':
    sys.exit(main())
