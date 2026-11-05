begin;
alter table public.profiles add column deleted_at timestamptz;
create index profiles_role_idx on public.profiles(role_id);
create index change_requests_rule_idx on public.change_requests(rule_id);
create index change_requests_status_idx on public.change_requests(status,updated_at desc);
create index test_evidence_version_idx on public.test_evidence(version_id,created_at desc);
create index comments_request_idx on public.comments(request_id,created_at);
create index audit_events_time_idx on public.audit_events(created_at desc);
commit;
