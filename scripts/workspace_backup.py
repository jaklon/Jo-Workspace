"""Offline creation and isolated preparation of Jo Workspace recovery archives."""
import argparse
import getpass
import json
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'backend'))
from backup_archive import check_recovery_links, create_archive, prepare_restore, stage_archive  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description='Cadangan Jo Workspace (jalankan saat backend berhenti).')
    sub = parser.add_subparsers(dest='command', required=True)
    create = sub.add_parser('create')
    create.add_argument('--browser', type=Path, required=True)
    create.add_argument('--runtime', type=Path, required=True)
    create.add_argument('--workspace', type=Path, required=True)
    create.add_argument('--output', type=Path, required=True)
    create.add_argument('--portable-evidence', action='store_true', help='Minta frasa sandi untuk evidence DPAPI portabel.')
    preview = sub.add_parser('preview')
    preview.add_argument('archive', type=Path)
    restore = sub.add_parser('restore')
    restore.add_argument('archive', type=Path)
    restore.add_argument('--destination', type=Path, required=True)
    restore.add_argument('--portable-evidence', action='store_true', help='Minta frasa sandi evidence portabel.')
    schedule = sub.add_parser('schedule-config')
    schedule.add_argument('--config', type=Path, required=True)
    schedule.add_argument('--browser', type=Path, required=True)
    schedule.add_argument('--browser-store', type=Path, action='append', required=True)
    schedule.add_argument('--runtime', type=Path, required=True)
    schedule.add_argument('--workspace', type=Path, required=True)
    schedule.add_argument('--destination', type=Path, required=True)
    schedule.add_argument('--retention', type=int, default=7)
    scheduled = sub.add_parser('schedule-run')
    scheduled.add_argument('--config', type=Path, required=True)
    register = sub.add_parser('schedule-register')
    register.add_argument('--config', type=Path, required=True)
    args = parser.parse_args()
    if args.command == 'create':
        if args.browser.stat().st_size > 50 * 1024 * 1024:
            raise ValueError('Snapshot browser melebihi 50 MB.')
        state = json.loads(args.browser.read_text(encoding='utf-8-sig'))
        phrase = getpass.getpass('Frasa sandi evidence portabel (minimal 12 karakter): ') if args.portable_evidence else None
        if phrase and phrase != getpass.getpass('Ulangi frasa sandi: '):
            raise ValueError('Frasa sandi tidak sama.')
        from runtime_lock import runtime_lock
        with runtime_lock(args.runtime):
            result = create_archive(args.output, args.runtime, args.workspace, state, phrase)
    elif args.command == 'preview':
        with tempfile.TemporaryDirectory(prefix='jo-preview-') as parent:
            stage, manifest = stage_archive(args.archive, parent)
            missing = check_recovery_links(stage)
            result = {'created_at': manifest.get('created_at'), 'files': len(manifest['files']),
                      'total_bytes': sum(item['size'] for item in manifest['files']),
                      'excluded': manifest.get('excluded', []),
                      'missing_attachments': missing, 'portable_evidence': manifest.get('portable_evidence', False)}
            shutil.rmtree(stage)
    elif args.command == 'restore':
        phrase = getpass.getpass('Frasa sandi evidence portabel: ') if args.portable_evidence else None
        result = prepare_restore(args.archive, args.destination, phrase)
    elif args.command == 'schedule-config':
        from backup_schedule import save_schedule
        phrase = getpass.getpass('Frasa sandi evidence portabel (minimal 12 karakter): ')
        if phrase != getpass.getpass('Ulangi frasa sandi: '):
            raise ValueError('Frasa sandi tidak sama.')
        result = save_schedule(args.config, runtime=args.runtime, workspace=args.workspace,
                               browser=args.browser, browser_stores=args.browser_store, destination=args.destination,
                               retention=args.retention, passphrase=phrase)
    elif args.command == 'schedule-run':
        from backup_schedule import run_schedule
        result = run_schedule(args.config)
    else:
        from backup_schedule import register_schedule
        result = register_schedule(args.config, Path(__file__))
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print('Cadangan/pemulihan gagal: ' + str(exc), file=sys.stderr)
        sys.exit(1)
