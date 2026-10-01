# Courtside Padel

Padel club app for admins, organisers and players: games across courts with level-matched pairs, Americano ladders, match clocks, adjusting levels, leagues and memberships.

- **Front end:** one static page (`index.html`), hosted on GitHub Pages.
- **Database and sign-in:** Supabase (Postgres) with Google sign-in.
- **Permissions:** enforced by the database itself (row-level security in `supabase/schema.sql`).

| Role | Who | Can |
|---|---|---|
| Admin | Emails in `app_admins` (mink.sumana@gmail.com) | Everything: clubs, organisers, memberships, pricing, any profile |
| Organiser | Players listed as organisers of a club | Games, rounds, scores, leagues and starting levels at their club |
| Player | Anyone signed in | Their own profile and sign-ups; read the club's games and tables |

## Files

| File | What it is |
|---|---|
| `index.html` | The app |
| `config.js` | Your Supabase project URL and public key |
| `vendor/supabase.js` | Supabase client library (v2.117.2), bundled so the site has no outside dependency |
| `supabase/schema.sql` | Tables, permission rules and live updates. Run once in Supabase. |

The club's existing data has already been loaded into the Supabase project, so there is no import file in this repository.

## Setup

Already done: Supabase project `courtside-padel` (London) created, `supabase/schema.sql` applied, club data loaded, `config.js` filled in.

Still to do:
1. Turn on Google sign-in (Google Cloud OAuth client → Supabase Authentication → Sign In / Providers → Google).
2. Push this folder to a GitHub repository named `courtside-padel` and turn on Pages (Settings → Pages → Deploy from branch → `main` / root).
3. In Supabase Authentication → URL Configuration, set the Site URL and a Redirect URL to the Pages address.
4. Sign in as mink.sumana@gmail.com. The earlier app's profile, games and sign-ups move to that Google account automatically.

Adding another admin takes two changes: add their email to `app_admins` in Supabase, and add it to `adminEmails` in `config.js`.
