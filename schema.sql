-- Run this once in Supabase: SQL Editor > New query > Run


create sequence if not exists request_number_seq;


create table if not exists accounts (

    id               bigint generated always as identity primary key,
    role             text not null check (role in ('resident', 'staff')),
    name             text not null,
    email            text not null,
    password_hash    text not null,
    address          text,
    contact          text,

    reset_code_hash  text,
    reset_expires_at timestamptz,

    created_at       timestamptz not null default now()

);

create unique index if not exists accounts_email_unique
    on accounts (lower(email));


create table if not exists requests (

    id             bigint generated always as identity primary key,

    request_no     text not null unique default (
        'BR-' || to_char(now(), 'YYYY') || '-' ||
        lpad(nextval('request_number_seq')::text, 5, '0')
    ),

    resident_id    bigint not null references accounts (id) on delete cascade,

    document_type  text not null check (document_type in (
        'Barangay Clearance',
        'Barangay Certificate',
        'Certificate of Indigency',
        'Certificate of Residency',
        'Business Clearance',
        'Other'
    )),

    purpose        text not null,

    release_method text not null check (release_method in (
        'Digital Copy',
        'Physical Copy'
    )),

    status         text not null default 'Pending' check (status in (
        'Pending',
        'Processing',
        'Ready for Release',
        'Completed',
        'Rejected'
    )),

    created_at     timestamptz not null default now(),
    updated_at     timestamptz not null default now()

);

create index if not exists requests_resident_idx on requests (resident_id);
create index if not exists requests_status_idx   on requests (status);


-- Only this project's server (using the service_role key) may touch
-- these tables. Nobody can read them with the public "anon" key.

alter table accounts enable row level security;
alter table requests enable row level security;

revoke all on table accounts from anon, authenticated;
revoke all on table requests from anon, authenticated;
