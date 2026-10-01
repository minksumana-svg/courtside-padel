// Courtside Padel — connection settings.
// Supabase project "courtside-padel" (London). The publishable key is meant to be public;
// the database's row-level security decides what each person can do.
window.COURTSIDE_CONFIG = {
  supabaseUrl: "https://uvkqihovwzebmukhfqry.supabase.co",
  supabaseAnonKey: "sb_publishable_OWNeuiXC83Fj65AfOpRCUA_sj_E_utv",
  // Who sees the Admin screens. Must match the emails in the app_admins table (schema.sql).
  adminEmails: ["mink.sumana@gmail.com"]
};
