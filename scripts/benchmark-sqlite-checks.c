/* Read-only SQLite diagnostics for disposable benchmark projections.
 * Compile with the application's bundled sqlite3.c and its build.rs defines
 * (including SQLITE_ENABLE_DBSTAT_VTAB), not the system library.
 * Usage: sqlite-checks DATABASE CACHE_KIB quick|integrity|foreign_keys|sizes [TABLE]
 * TABLE restricts integrity/foreign_keys only. No application state is changed.
 */
#include "sqlite3.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>

static double seconds(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

static long long io_bytes(const char *key) {
    FILE *f = fopen("/proc/self/io", "r");
    char name[64];
    long long value = 0, result = -1;
    if (!f) return -1;
    while (fscanf(f, "%63s %lld", name, &value) == 2)
        if (!strcmp(name, key)) result = value;
    fclose(f);
    return result;
}

int main(int argc, char **argv) {
    if (argc < 4 || argc > 5) return 2;
    char *end;
    long cache = strtol(argv[2], &end, 10);
    if (*end || cache < 1 || cache > 262144) return 2;
    const char *mode = argv[3];
    int sizes = !strcmp(mode, "sizes");
    const char *pragma = !strcmp(mode, "quick") ? "quick_check" :
        !strcmp(mode, "integrity") ? "integrity_check" :
        !strcmp(mode, "foreign_keys") ? "foreign_key_check" : NULL;
    if ((!sizes && !pragma) || (argc == 5 && (sizes || !strcmp(mode, "quick")))) return 2;
    sqlite3 *db = NULL;
    int rc = sqlite3_open_v2(argv[1], &db, SQLITE_OPEN_READONLY, NULL);
    if (rc != SQLITE_OK) goto error;
    char *config = sqlite3_mprintf("PRAGMA query_only=ON; PRAGMA cache_size=-%ld;", cache);
    rc = sqlite3_exec(db, config, NULL, NULL, NULL);
    sqlite3_free(config);
    if (rc != SQLITE_OK) goto error;
    char *sql = sizes ? sqlite3_mprintf(
        "SELECT name,pagetype,count(*),sum(pgsize),sum(payload),sum(unused) "
        "FROM dbstat GROUP BY name,pagetype ORDER BY name,pagetype") :
        argc == 5 ? sqlite3_mprintf("PRAGMA %s(%Q)", pragma, argv[4]) :
        sqlite3_mprintf("PRAGMA %s", pragma);
    sqlite3_stmt *statement = NULL;
    rc = sqlite3_prepare_v2(db, sql, -1, &statement, NULL);
    sqlite3_free(sql);
    if (rc != SQLITE_OK) goto error;
    int current, high;
    sqlite3_db_status(db, SQLITE_DBSTATUS_CACHE_HIT, &current, &high, 1);
    sqlite3_db_status(db, SQLITE_DBSTATUS_CACHE_MISS, &current, &high, 1);
    long long read_start = io_bytes("read_bytes:"), write_start = io_bytes("write_bytes:");
    double started = seconds();
    fprintf(stderr, "starting %s cache=%ld KiB SQLite=%s\n", mode, cache, sqlite3_libversion());
    fflush(stderr);
    long long rows = 0, findings = 0;
    while ((rc = sqlite3_step(statement)) == SQLITE_ROW) {
        rows++;
        if (sizes) {
            printf("%s,%s,%lld,%lld,%lld,%lld\n", sqlite3_column_text(statement, 0),
                sqlite3_column_text(statement, 1), sqlite3_column_int64(statement, 2),
                sqlite3_column_int64(statement, 3), sqlite3_column_int64(statement, 4),
                sqlite3_column_int64(statement, 5));
        } else if (!strcmp(mode, "foreign_keys") ||
            strcmp((const char *)sqlite3_column_text(statement, 0), "ok")) findings++;
    }
    double elapsed = seconds() - started;
    sqlite3_finalize(statement);
    if (rc != SQLITE_DONE) goto error;
    int hits, misses, used;
    sqlite3_db_status(db, SQLITE_DBSTATUS_CACHE_HIT, &hits, &high, 0);
    sqlite3_db_status(db, SQLITE_DBSTATUS_CACHE_MISS, &misses, &high, 0);
    sqlite3_db_status(db, SQLITE_DBSTATUS_CACHE_USED, &used, &high, 0);
    struct rusage usage;
    getrusage(RUSAGE_SELF, &usage);
    printf("{\"mode\":\"%s\",\"sqlite_version\":\"%s\",\"cache_kib\":%ld,"
        "\"seconds\":%.6f,\"rows\":%lld,\"findings\":%lld,\"cache_hits\":%d,"
        "\"cache_misses\":%d,\"cache_used_bytes\":%d,\"peak_rss_kib\":%ld,"
        "\"read_bytes\":%lld,\"write_bytes\":%lld}\n", mode, sqlite3_libversion(), cache,
        elapsed, rows, findings, hits, misses, used, usage.ru_maxrss,
        io_bytes("read_bytes:") - read_start, io_bytes("write_bytes:") - write_start);
    sqlite3_close(db);
    return findings ? 1 : 0;
error:
    fprintf(stderr, "SQLite error %d: %s\n", rc, db ? sqlite3_errmsg(db) : "open failed");
    sqlite3_close(db);
    return 1;
}
