/**
 * Function-call control. Functions are a bypass surface: several built-ins read
 * files, open network connections, or execute SQL passed as a *string* (so the
 * analyzer never sees the inner tables). This module gates which functions a
 * statement may call.
 */

/**
 * Built-in functions that read data/files, do I/O, or run arbitrary SQL — always
 * blocked in the default (denylist) mode. Matched by bare name, so a schema
 * qualifier like `pg_catalog.pg_read_file` is covered too.
 */
export const DANGEROUS_FUNCTIONS: ReadonlySet<string> = new Set([
  // Execute SQL from a string argument — total analyzer bypass.
  'dblink', 'dblink_connect', 'dblink_connect_u', 'dblink_exec', 'dblink_open',
  'dblink_fetch', 'dblink_send_query', 'dblink_get_result',
  'query_to_xml', 'query_to_xmlschema', 'query_to_xml_and_xmlschema',
  'cursor_to_xml', 'cursor_to_xmlschema',
  'table_to_xml', 'table_to_xmlschema', 'table_to_xml_and_xmlschema',
  'schema_to_xml', 'schema_to_xmlschema', 'schema_to_xml_and_xmlschema',
  'database_to_xml', 'database_to_xmlschema', 'database_to_xml_and_xmlschema',
  'connectby', // tablefunc: takes a relation name as a string
  'ts_rewrite', // 3-arg form runs its text argument as SQL to fetch substitution rules
  // Server-side file access.
  'pg_read_file', 'pg_read_binary_file', 'pg_ls_dir', 'pg_stat_file',
  'pg_ls_logdir', 'pg_ls_waldir', 'pg_ls_tmpdir', 'pg_ls_archive_statusdir',
  'pg_current_logfile',
  // adminpack file functions — write/read/rename/unlink server files and list the
  // log dir. Not matched by the `pg_read`/`pg_ls_` prefixes (they are `pg_file_*` /
  // `pg_logdir_ls`), so the filesystem-isolation guarantee leaks without them.
  'pg_file_write', 'pg_file_read', 'pg_file_sync', 'pg_file_rename',
  'pg_file_unlink', 'pg_file_length', 'pg_logdir_ls',
  // Server configuration & auth/HBA-file readers — leak GUCs (incl. secrets
  // stashed in custom GUCs), file paths, and the pg_hba/pg_ident rules.
  'current_setting', 'pg_show_all_settings', 'pg_settings_get_flags',
  'pg_hba_file_rules', 'pg_ident_file_mappings', 'pg_show_all_file_settings',
  'pg_config',
  // Large objects (can read/write server files and arbitrary OIDs).
  'lo_import', 'lo_export', 'lo_get', 'lo_put', 'lo_from_bytea', 'lo_creat',
  'lo_create', 'lo_unlink', 'lo_open', 'loread', 'lowrite',
  // Denial of service.
  'pg_sleep', 'pg_sleep_for', 'pg_sleep_until',
  // Affect other sessions / server / session state (incl. search_path).
  'pg_terminate_backend', 'pg_cancel_backend', 'pg_reload_conf',
  'pg_rotate_logfile', 'pg_stat_get_activity', 'pg_export_snapshot',
  'set_config', 'setval', 'pg_notify', // pg_notify = out-of-band exfil channel
  // Cluster administration — WAL, backup, replication, recovery, promotion.
  // Untrusted callers must not disrupt the cluster (availability / DoS).
  'pg_promote', 'pg_switch_wal', 'pg_create_restore_point',
  'pg_backup_start', 'pg_backup_stop', 'pg_start_backup', 'pg_stop_backup',
  'pg_wal_replay_pause', 'pg_wal_replay_resume', 'pg_log_backend_memory_contexts',
  'pg_drop_replication_slot', 'pg_create_physical_replication_slot',
  'pg_create_logical_replication_slot', 'pg_replication_slot_advance',
  'pg_logical_emit_message',
  // Object definition / DDL leaks (reveal schema & source of any object).
  'pg_get_viewdef', 'pg_get_functiondef', 'pg_get_function_sqlbody',
  'pg_get_ruledef', 'pg_get_triggerdef', 'pg_get_indexdef', 'pg_get_constraintdef',
  'pg_get_partition_constraintdef', 'pg_get_expr', 'pg_get_userbyid',
  'pg_get_role_ddl', 'pg_get_database_ddl', 'pg_get_tablespace_ddl',
  'pg_get_statisticsobjdef', 'pg_get_acl', 'pg_get_sequence_data',
  // Object existence / metadata oracles — resolve a name against the catalog and
  // leak existence, size, OIDs, comments, or privileges of hidden objects,
  // sidestepping the introspection row-filter (they aren't relation references).
  'to_regclass', 'to_regproc', 'to_regprocedure', 'to_regoper', 'to_regoperator',
  'to_regtype', 'to_regrole', 'to_regnamespace', 'to_regcollation',
  'to_regdatabase', // PG18: name → database OID, a cross-database existence oracle
  'to_regtypemod',
  'obj_description', 'col_description', 'shobj_description',
  'pg_describe_object', 'pg_identify_object', 'pg_identify_object_as_address',
  'pg_get_object_address', // inverse of pg_identify_object: name → address (existence oracle)
  'pg_get_serial_sequence', 'pg_relation_filenode', 'pg_relation_filepath',
  'pg_filenode_relation', 'format_type',
  'pg_relation_size', 'pg_total_relation_size', 'pg_table_size', 'pg_indexes_size',
  // Cross-database / tablespace size & location: an existence + size oracle for
  // databases/tablespaces outside the model, and a server-path leak.
  'pg_database_size', 'pg_tablespace_size', 'pg_tablespace_location',
  'has_table_privilege', 'has_column_privilege', 'has_sequence_privilege',
  'has_any_column_privilege', 'has_schema_privilege', 'has_database_privilege',
  'has_function_privilege', 'has_foreign_data_wrapper_privilege',
  'has_server_privilege', 'has_tablespace_privilege', 'has_language_privilege',
  'has_type_privilege', 'has_parameter_privilege', 'has_largeobject_privilege',
  'pg_has_role', // role-membership oracle (same family as has_*_privilege)
  // Cluster internals / recon — control-file data (system identifier, checkpoint
  // LSNs), the server's own network address, replication slot state, and which
  // other backends block a given pid (cross-session visibility).
  'inet_server_addr', 'inet_server_port',
  'pg_get_replication_slots', 'pg_blocking_pids', 'pg_safe_snapshot_blocking_pids',
  'pg_isolation_test_session_is_blocked', // same cross-session blocking recon as pg_blocking_pids
  // WAL position / file naming / summarization — write-volume & replication-topology
  // recon. (Math on caller-supplied LSNs — pg_wal_lsn_diff, pg_lsn_* — stays allowed;
  // these read the *server's* live WAL state.) The bare-prefix singletons that the
  // `pg_*_wal` / `pg_get_wal_` prefixes below don't cover are listed explicitly.
  'pg_split_walfile_name', 'pg_is_wal_replay_paused',
  'pg_available_wal_summaries', 'pg_wal_summary_contents',
  // Replication slot/origin admin & recon not caught by the pg_replication_origin_ /
  // pg_logical_slot_ prefixes (different stems: pg_copy_*, pg_sync_*, pg_show_*).
  'pg_copy_logical_replication_slot', 'pg_copy_physical_replication_slot',
  'pg_sync_replication_slots', 'pg_show_replication_origin_status',
  // Server memory layout & cross-database enumeration; system-collation import (admin).
  'pg_get_dsm_registry_allocations', 'pg_tablespace_databases', 'pg_import_system_collations',
  // The proxy's own connection address (symmetric with inet_server_*); infra recon,
  // no application use. (pg_postmaster_start_time / pg_conf_load_time left allowed —
  // benign uptime metadata commonly read by monitoring dashboards.)
  'inet_client_addr', 'inet_client_port',
  // Planner-statistics MUTATION (PG18) — pg_restore_*_stats INJECTS arbitrary stats
  // and pg_clear_*_stats wipes them; on a shared table that poisons the planner for
  // EVERY tenant (cross-tenant DoS / integrity). Covered by the pg_restore_/pg_clear_
  // prefixes below; named here for the audit trail.
  'pg_restore_relation_stats', 'pg_restore_attribute_stats', 'pg_restore_extended_stats',
  'pg_clear_relation_stats', 'pg_clear_attribute_stats', 'pg_clear_extended_stats',
  // Cluster-wide admin / availability (heavy online operations, DoS).
  'pg_enable_data_checksums', 'pg_disable_data_checksums',
  'pg_log_standby_snapshot', 'pg_nextoid', 'pg_stop_making_pinned_objects',
  // Cross-session / cluster-wide state recon — the SRFs behind the deny-most
  // pg_locks / pg_prepared_xacts views leak every session's locks and 2PC txns.
  'pg_lock_status', 'pg_prepared_xact',
  // Definition leaks completing the pg_get_*def family — partition key, extended-stats
  // object columns/exprs, and function signatures/defaults (schema disclosure of any
  // object by OID; pg_proc/pg_statistic_ext are deny-most so utility is low, but this
  // is the same leak class as the already-blocked pg_get_functiondef/_statisticsobjdef).
  'pg_get_partkeydef', 'pg_get_statisticsobjdef_columns', 'pg_get_statisticsobjdef_expressions',
  // Sequence value/parameters — current value of any sequence by OID is a
  // business-volume metric leak (pg_sequences view is itself deny-most).
  'pg_sequence_parameters', 'pg_sequence_last_value',
  // Partition-hierarchy enumeration — leaks child/parent partition OIDs, exactly the
  // inheritance structure the read-path fails closed on; an OID-gated structural leak.
  'pg_partition_tree', 'pg_partition_ancestors', 'pg_partition_root',
  // Extension / loaded-module inventory — recon of installed attack surface (versions
  // map to known CVEs); pg_extension_config_dump also mutates dump state.
  'pg_available_extensions', 'pg_available_extension_versions', 'pg_extension_update_paths',
  'pg_extension_config_dump', 'pg_get_loaded_modules',
  // Logical-replication topology — member tables/sequences of a publication (object
  // existence + replication layout; pg_publication* catalogs are deny-most).
  'pg_get_publication_tables', 'pg_get_publication_sequences',
  // Server memory-context dump — internal layout recon.
  'pg_get_backend_memory_contexts',
])

/**
 * Dangerous function families, matched by name prefix so newly-added members are
 * covered automatically (`pg_read_*`, `pg_ls_*`, `lo_*`, `dblink*`, server
 * internals, advisory locks).
 */
const DANGEROUS_PREFIXES: readonly string[] = [
  'pg_read', 'pg_ls_', 'lo_', 'dblink', 'binary_upgrade_', 'pg_advisory',
  'pg_try_advisory', // advisory-lock DoS: the try-variants the `pg_advisory` prefix misses
  'pg_file_', // adminpack file write/read/rename/unlink (server filesystem access)
  'pg_control_', // control-file readers: system/checkpoint/recovery/init metadata
  // WAL state recon (write-volume / replication topology). Deliberately NOT a bare
  // `pg_wal` prefix — that would over-block the benign LSN math `pg_wal_lsn_diff`.
  'pg_current_wal', 'pg_last_wal', 'pg_walfile', 'pg_get_wal_',
  'pg_get_shmem', // server shared-memory allocation map (incl. _numa)
  'pg_stat_reset', // reset monitoring/replication-slot stats (state mutation)
  'pg_restore_', // PG18 planner-statistics INJECTION (relation/attribute/extended)
  'pg_clear_', // PG18 planner-statistics wipe (distinct from the benign pg_stat_clear_snapshot)
  'pg_partition_', // partition-hierarchy enumeration (tree/ancestors/root)
  'pg_get_function_', // function signature/result/arg-default leaks (NOT pg_get_functiondef, already listed)
  'crosstab', // tablefunc: crosstab/crosstab2/3/4 execute a SQL string argument
  // Replication administration / stream consumption.
  'pg_replication_origin_', 'pg_logical_slot_',
  // Per-backend / per-database statistics accessors. The `pg_stat_activity` view
  // and `pg_stat_get_activity` are blocked, but the underlying accessors
  // (`pg_stat_get_backend_activity(pid)` etc.) can read another session's live
  // query text and other backends'/databases' stats — a cross-tenant leak.
  'pg_stat_get_',
]

/** Harmless built-ins always permitted in allowlist mode (extend via `list`). */
export const SAFE_FUNCTIONS: ReadonlySet<string> = new Set([
  'count', 'sum', 'avg', 'min', 'max', 'array_agg', 'string_agg', 'bool_and',
  'bool_or', 'every', 'row_number', 'rank', 'dense_rank',
  'lower', 'upper', 'length', 'char_length', 'trim', 'btrim', 'ltrim', 'rtrim',
  'substr', 'substring', 'replace', 'concat', 'concat_ws', 'left', 'right',
  'split_part', 'initcap', 'md5', 'position', 'strpos', 'format',
  'abs', 'round', 'ceil', 'ceiling', 'floor', 'mod', 'power', 'sqrt', 'trunc',
  'now', 'current_date', 'current_timestamp', 'current_time', 'date_trunc',
  'date_part', 'extract', 'age', 'to_char', 'to_date', 'to_timestamp', 'to_number',
  'coalesce', 'nullif', 'greatest', 'least',
]) // (many of these aren't even FuncCall nodes, but listing them is harmless)

/**
 * Built-in Postgres operator symbols (from `pg_operator.dat`). Operators are
 * function calls in disguise (`a @@ b` runs the function bound to `@@`), so a
 * custom operator could wrap a dangerous function. Built-ins are safe; anything
 * not here is treated as custom and denied unless explicitly allowed.
 */
export const BUILTIN_OPERATORS: ReadonlySet<string> = new Set([
  '-', '->', '->>', '-|-', '!!', '!~', '!~*', '!~~', '!~~*', '?', '?-', '?-|',
  '?&', '?#', '?|', '?||', '@', '@-@', '@?', '@@', '@@@', '@>', '*', '*<', '*<=',
  '*<>', '*=', '*>', '*>=', '/', '&', '&&', '&<', '&<|', '&>', '#', '#-', '##',
  '#>', '#>>', '%', '^', '^@', '+', '<', '<->', '<@', '<^', '<<', '<<=', '<<|',
  '<=', '<>', '=', '>', '>^', '>=', '>>', '>>=', '|', '|/', '|&>', '|>>', '||',
  '||/', '~', '~*', '~<=~', '~<~', '~=', '~>=~', '~>~', '~~', '~~*',
])

export interface FunctionPolicy {
  /**
   * `denylist` (default): permit everything except {@link DANGEROUS_FUNCTIONS}
   * and any extra names in `list`. `allowlist`: permit only `list` plus
   * {@link SAFE_FUNCTIONS}.
   */
  mode?: 'denylist' | 'allowlist'
  /** Extra functions to block (denylist) or to permit (allowlist). */
  list?: readonly string[]
  /** Custom (non-built-in) operators to permit. Built-in operators are always allowed. */
  allowOperators?: readonly string[]
}

/**
 * Split a possibly schema-qualified name into its qualifier and bare name.
 * Operator and function names cannot contain `.`, so the last segment is the
 * bare name and anything before it is the schema qualifier.
 */
function splitQualified(name: string): { schema?: string; base: string } {
  const dot = name.lastIndexOf('.')
  return dot === -1 ? { base: name } : { schema: name.slice(0, dot), base: name.slice(dot + 1) }
}

/** Whether a schema qualifier denotes a built-in (absent, or `pg_catalog`). */
function isBuiltinSchema(schema: string | undefined): boolean {
  return schema === undefined || schema === 'pg_catalog'
}

/**
 * Whether an operator may be used. A built-in symbol (unqualified or
 * `pg_catalog`-qualified) is allowed; a schema-qualified operator is by
 * definition user-defined (it could wrap any function) and is denied unless its
 * exact qualified form is listed in `allowOperators`.
 */
export function operatorAllowed(policy: FunctionPolicy | undefined, operator: string): boolean {
  if (policy?.allowOperators?.includes(operator)) return true
  const { schema, base } = splitQualified(operator)
  if (!isBuiltinSchema(schema)) return false
  return BUILTIN_OPERATORS.has(base) || (policy?.allowOperators?.includes(base) ?? false)
}

function isDangerous(fn: string): boolean {
  return DANGEROUS_FUNCTIONS.has(fn) || DANGEROUS_PREFIXES.some((p) => fn.startsWith(p))
}

/**
 * Whether a function (lower-cased, possibly schema-qualified) may be called. A
 * schema qualifier other than `pg_catalog` denotes a user-defined function, so
 * matching the bare name against {@link SAFE_FUNCTIONS} or an allow-list entry is
 * not enough — the call must match the exact qualified form. Dangerous built-ins
 * stay blocked under any (or no) qualifier.
 */
export function functionAllowed(policy: FunctionPolicy | undefined, name: string): boolean {
  const lower = name.toLowerCase()
  const { schema, base } = splitQualified(lower)
  const list = policy?.list ?? []
  if (policy?.mode === 'allowlist') {
    if (list.includes(lower)) return true // exact match (qualified or bare)
    return isBuiltinSchema(schema) && (SAFE_FUNCTIONS.has(base) || list.includes(base))
  }
  if (isDangerous(base)) return false
  return !list.includes(lower) && !list.includes(base)
}
