/**
 * Centralized error model. Every rejection the analyzer can produce has a code
 * in {@link ViolationCode} and is constructed through {@link Violations}, so
 * wording stays consistent and call sites never build messages inline.
 */

/** The reason a statement was rejected. */
export enum ViolationCode {
  ParseError = 'PARSE_ERROR',
  EmptyStatement = 'EMPTY_STATEMENT',
  StatementStacking = 'STATEMENT_STACKING',
  /** Non-DML / DDL / utility statement (the "no schema altering" guarantee). */
  StatementNotAllowed = 'STATEMENT_NOT_ALLOWED',
  SchemaNotVisible = 'SCHEMA_NOT_VISIBLE',
  RelationNotVisible = 'RELATION_NOT_VISIBLE',
  /** A secret-bearing system catalog (e.g. pg_authid) blocked despite introspection. */
  SystemCatalogBlocked = 'SYSTEM_CATALOG_BLOCKED',
  /** A catalog relation that cannot be row-filtered and was not opted into. */
  IntrospectionNotAllowed = 'INTROSPECTION_NOT_ALLOWED',
  /** A function that is not permitted (dangerous, or outside the allow-list). */
  FunctionNotAllowed = 'FUNCTION_NOT_ALLOWED',
  /** A non-built-in operator that was not explicitly allowed. */
  OperatorNotAllowed = 'OPERATOR_NOT_ALLOWED',
  /** A `reg*` object-resolution cast (`'x'::regclass`) — a catalog/OID oracle. */
  TypeCastNotAllowed = 'TYPE_CAST_NOT_ALLOWED',
  /** A read of a table that has inheritance/partition children (reads them too). */
  InheritedRelationBlocked = 'INHERITED_RELATION_BLOCKED',
  ColumnNotReadable = 'COLUMN_NOT_READABLE',
  InsertNotAllowed = 'INSERT_NOT_ALLOWED',
  UpdateNotAllowed = 'UPDATE_NOT_ALLOWED',
  DeleteNotAllowed = 'DELETE_NOT_ALLOWED',
  ColumnNotWritable = 'COLUMN_NOT_WRITABLE',
  /** A required rewrite (e.g. `*` expansion) could not be applied safely. */
  RewriteFailed = 'REWRITE_FAILED',
  NotImplemented = 'NOT_IMPLEMENTED',
}

/** A single, immutable rejection reason. */
export interface Violation {
  readonly code: ViolationCode
  readonly message: string
}

function make(code: ViolationCode, message: string): Violation {
  return { code, message }
}

/**
 * The one place violations are constructed. Keeping wording here means a code
 * and its phrasing can never drift apart across the analyzer.
 */
export const Violations = {
  parseError(detail: string): Violation {
    return make(ViolationCode.ParseError, `could not parse statement: ${detail}`)
  },
  emptyStatement(): Violation {
    return make(ViolationCode.EmptyStatement, 'empty statement')
  },
  statementStacking(found: number): Violation {
    return make(
      ViolationCode.StatementStacking,
      `expected a single statement, found ${found}`,
    )
  },
  statementNotAllowed(type: string): Violation {
    return make(
      ViolationCode.StatementNotAllowed,
      `statement type ${type} is not permitted; only SELECT/INSERT/UPDATE/DELETE are allowed`,
    )
  },
  schemaNotVisible(schema: string): Violation {
    return make(
      ViolationCode.SchemaNotVisible,
      `schema "${schema}" is not accessible to this role`,
    )
  },
  relationNotVisible(relation: string): Violation {
    return make(
      ViolationCode.RelationNotVisible,
      `relation "${relation}" is not visible to this role`,
    )
  },
  systemCatalogBlocked(relation: string): Violation {
    return make(
      ViolationCode.SystemCatalogBlocked,
      `system catalog "${relation}" is blocked from introspection (may expose secrets or other roles' data)`,
    )
  },
  introspectionNotAllowed(relation: string): Violation {
    return make(
      ViolationCode.IntrospectionNotAllowed,
      `catalog "${relation}" cannot be row-filtered and is not permitted; opt in via introspection.allowUnfiltered`,
    )
  },
  functionNotAllowed(name: string): Violation {
    return make(ViolationCode.FunctionNotAllowed, `function "${name}" is not permitted`)
  },
  operatorNotAllowed(operator: string): Violation {
    return make(
      ViolationCode.OperatorNotAllowed,
      `operator "${operator}" is not a built-in and is not permitted`,
    )
  },
  typeCastNotAllowed(type: string): Violation {
    return make(
      ViolationCode.TypeCastNotAllowed,
      `cast to "${type}" is not permitted (it resolves arbitrary catalog objects)`,
    )
  },
  inheritedRelationBlocked(relation: string): Violation {
    return make(
      ViolationCode.InheritedRelationBlocked,
      `relation "${relation}" has inheritance/partition children; reading it reads them too (set allowInherited to permit)`,
    )
  },
  columnNotReadable(column: string, relation: string): Violation {
    return make(
      ViolationCode.ColumnNotReadable,
      `column "${column}" of "${relation}" is not readable by this role`,
    )
  },
  rewriteFailed(detail: string): Violation {
    return make(ViolationCode.RewriteFailed, `could not safely rewrite statement: ${detail}`)
  },
  insertNotAllowed(relation: string): Violation {
    return make(ViolationCode.InsertNotAllowed, `INSERT into "${relation}" is not permitted`)
  },
  updateNotAllowed(relation: string): Violation {
    return make(ViolationCode.UpdateNotAllowed, `UPDATE on "${relation}" is not permitted`)
  },
  deleteNotAllowed(relation: string): Violation {
    return make(ViolationCode.DeleteNotAllowed, `DELETE on "${relation}" is not permitted`)
  },
  columnNotWritable(column: string, relation: string): Violation {
    return make(
      ViolationCode.ColumnNotWritable,
      `column "${column}" of "${relation}" is not writable by this role`,
    )
  },
} as const
