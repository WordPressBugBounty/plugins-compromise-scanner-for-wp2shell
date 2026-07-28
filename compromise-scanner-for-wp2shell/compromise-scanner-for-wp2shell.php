<?php
/**
 * Plugin Name:       Compromise Scanner for wp2shell
 * Plugin URI:        https://github.com/eyesecurity/wp2shell-compromise-scanner-plugin
 * Description:       Read-only forensic scanner that inspects the database and plugin directory for artifacts left by the WordPress core exploit chain tracked as CVE-2026-63030 and CVE-2026-60137. It reports a scored verdict on its own screen and changes nothing on the site.
 * Version:           1.1.0
 * Requires at least: 5.6
 * Requires PHP:      7.2
 * Author:            Eye Security
 * Author URI:        https://www.eye.security/
 * License:           GPL-3.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-3.0.html
 * Text Domain:       compromise-scanner-for-wp2shell
 *
 * @package CompromiseScannerForWp2shell
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'WP2SHELL_SCAN_VERSION', '1.1.0' );
define( 'WP2SHELL_SCAN_SLUG', 'compromise-scanner-for-wp2shell' );
define( 'WP2SHELL_SCAN_OPTION', 'wp2shell_scan_result' );
// Public disclosure date of the wp2shell chain; the date-window checks and the evidence
// export both key off this. See CLAUDE.md before changing it.
define( 'WP2SHELL_SCAN_DISCLOSURE', '2026-07-17 00:00:00' );
// Row cap per evidence table and character cap per content excerpt in the export, so the
// archive stays reviewable and bounded even on a busy or heavily seeded site.
define( 'WP2SHELL_SCAN_EVIDENCE_MAX_ROWS', 500 );
define( 'WP2SHELL_SCAN_EVIDENCE_MAX_CHARS', 2000 );

/**
 * Classify the running core version against the wp2shell fix releases.
 *
 * Affected branches (fixed in 6.8.6 / 6.9.5 / 7.0.2): 6.8.0-6.8.5, 6.9.0-6.9.4, 7.0.0-7.0.1.
 * This is reported as its own status, kept separate from the forensic verdict: "vulnerable" means
 * the fix is not present (independent of whether the site was ever exploited); "patched" means it is.
 *
 * @return array{status:string,version:string,affected:bool}
 */
function wp2shell_scan_version_status() {
	$version = isset( $GLOBALS['wp_version'] ) ? (string) $GLOBALS['wp_version'] : '';
	$base    = preg_replace( '/[^0-9.].*$/', '', $version );
	if ( '' === $base ) {
		return array( 'status' => 'unknown', 'version' => $version, 'affected' => false );
	}
	$affected = ( version_compare( $base, '6.8.0', '>=' ) && version_compare( $base, '6.8.6', '<' ) )
		|| ( version_compare( $base, '6.9.0', '>=' ) && version_compare( $base, '6.9.5', '<' ) )
		|| ( version_compare( $base, '7.0.0', '>=' ) && version_compare( $base, '7.0.2', '<' ) );
	if ( $affected ) {
		$status = 'vulnerable';
	} elseif ( version_compare( $base, '6.8.0', '<' ) ) {
		// Predates the tracked/backported branches — unsupported; cannot confirm, recommend upgrading.
		$status = 'unknown';
	} else {
		$status = 'patched';
	}
	return array( 'status' => $status, 'version' => $version, 'affected' => $affected );
}

/**
 * Whether the running core is in the affected wp2shell range (fix not present).
 *
 * @return bool
 */
function wp2shell_scan_core_vulnerable() {
	$s = wp2shell_scan_version_status();
	return ! empty( $s['affected'] );
}

/**
 * Clear any cached verdict on (re)activation so a fresh install never shows stale results.
 */
register_activation_hook( __FILE__, function () {
	delete_option( WP2SHELL_SCAN_OPTION );
} );

/**
 * Run the read-only forensic scan.
 *
 * Each indicator carries a severity (for presentation) and a weight (for the score).
 * Verdict thresholds: score >= 50 "compromised", >= 25 "review", otherwise "clean".
 * The scan only reads; it never writes to posts, users, or files.
 *
 * @param bool $force Re-scan even if a cached result exists.
 * @return array
 */
function wp2shell_scan_scan( $force = false ) {
	if ( ! $force ) {
		$cached = get_option( WP2SHELL_SCAN_OPTION );
		// Serve the cached verdict only if it is fresh (under 24h); otherwise re-scan.
		if ( is_array( $cached ) && isset( $cached['score'], $cached['ran'] ) && ( time() - (int) $cached['ran'] ) < DAY_IN_SECONDS ) {
			return $cached;
		}
	}

	global $wpdb;
	// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- A forensic scanner must read the live database directly; the whole result is cached in the WP2SHELL_SCAN_OPTION option, so this does not run on every page load.
	$disclosure = WP2SHELL_SCAN_DISCLOSURE;
	$result     = array(
		'ran'     => time(),
		'score'   => 0,
		'version' => isset( $GLOBALS['wp_version'] ) ? (string) $GLOBALS['wp_version'] : '',
		'items'   => array(),
	);
	$add = function ( $label, $severity, $points, $detail, $hit ) use ( &$result ) {
		if ( $hit ) {
			$result['score'] += $points;
		}
		$result['items'][] = array(
			'label'    => $label,
			'severity' => $severity,
			'points'   => $points,
			'detail'   => $detail,
			'hit'      => (bool) $hit,
		);
	};
	$host = (string) wp_parse_url( home_url(), PHP_URL_HOST );

	/* oembed_cache artifacts — the write primitive the chain relies on. */
	$oc_total  = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->posts} WHERE post_type='oembed_cache'" );
	$oc_since  = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$wpdb->posts} WHERE post_type='oembed_cache' AND post_date >= %s", $disclosure ) );
	$oc_before = max( 0, $oc_total - $oc_since );
	$like_host = '%' . $wpdb->esc_like( $host ) . '%';
	$oc_loop   = (int) $wpdb->get_var( $wpdb->prepare(
		"SELECT COUNT(*) FROM {$wpdb->posts} WHERE post_type='oembed_cache' AND (post_content LIKE %s OR guid LIKE %s OR post_content LIKE %s)",
		$like_host,
		$like_host,
		'%/wp-json%'
	) );
	$add( __( 'oembed_cache entries referencing this site (loopback)', 'compromise-scanner-for-wp2shell' ), 'high', 25, (string) $oc_loop, $oc_loop > 0 );
	$add( __( 'Exactly three oembed_cache entries (the exploit seeds three)', 'compromise-scanner-for-wp2shell' ), 'medium', 15, (string) $oc_total, 3 === $oc_total );
	$add( __( 'oembed_cache entries created on or after the disclosure date', 'compromise-scanner-for-wp2shell' ), 'medium', 20, (string) $oc_since, $oc_since > 0 );
	$add( __( 'oembed_cache entries created before the disclosure date', 'compromise-scanner-for-wp2shell' ), 'low', 10, (string) $oc_before, $oc_before > 0 );

	/* Object-graph poisoning artifacts. */
	$pg_parent = (int) $wpdb->get_var(
		"SELECT COUNT(*) FROM {$wpdb->posts} WHERE post_type IN ('customize_changeset','nav_menu_item','request') AND post_parent >= 1000000"
	);
	$add( __( 'Posts with an implausibly high parent ID (>= 1,000,000)', 'compromise-scanner-for-wp2shell' ), 'high', 20, (string) $pg_parent, $pg_parent > 0 );
	$pg_name = (int) $wpdb->get_var(
		"SELECT COUNT(*) FROM {$wpdb->posts} WHERE post_type IN ('customize_changeset','nav_menu_item','request','oembed_cache')
		 AND (post_title IN ('trigger','nav','parse','changeset','seed') OR post_name IN ('trigger','nav','parse','changeset','seed'))"
	);
	$add( __( 'Posts using known proof-of-concept titles or slugs', 'compromise-scanner-for-wp2shell' ), 'high', 20, (string) $pg_name, $pg_name > 0 );
	$cc = (int) $wpdb->get_var( $wpdb->prepare(
		"SELECT COUNT(*) FROM {$wpdb->posts} WHERE post_type='customize_changeset' AND post_date >= %s",
		$disclosure
	) );
	$add( __( 'customize_changeset entries created on or after disclosure', 'compromise-scanner-for-wp2shell' ), 'medium', 15, (string) $cc, $cc > 0 );

	/* Account artifacts. */
	$wp2_logins = $wpdb->get_col( "SELECT user_login FROM {$wpdb->users} WHERE user_login LIKE 'wp2\\_%'" );
	$add( __( 'Accounts using the wp2_ login prefix (exploit default)', 'compromise-scanner-for-wp2shell' ), 'critical', 25, $wp2_logins ? implode( ', ', $wp2_logins ) : '', ! empty( $wp2_logins ) );
	$wp2_emails = $wpdb->get_col( "SELECT user_email FROM {$wpdb->users} WHERE user_email LIKE '%@wp2shell.invalid'" );
	$add( __( 'Accounts using an @wp2shell.invalid email (exploit default)', 'compromise-scanner-for-wp2shell' ), 'critical', 20, $wp2_emails ? implode( ', ', $wp2_emails ) : '', ! empty( $wp2_emails ) );
	$founder = (int) $wpdb->get_var( "SELECT MIN(ID) FROM {$wpdb->users}" );
	// Administrators only: the exploit creates an admin, and counting every registration would
	// flag ordinary subscriber sign-ups on sites with open registration.
	$new_admins = (int) $wpdb->get_var( $wpdb->prepare(
		"SELECT COUNT(DISTINCT u.ID) FROM {$wpdb->users} u
		 INNER JOIN {$wpdb->usermeta} m ON m.user_id = u.ID
		 WHERE u.user_registered >= %s AND u.ID > %d AND m.meta_key = %s AND m.meta_value LIKE %s",
		$disclosure,
		$founder,
		$wpdb->get_blog_prefix() . 'capabilities',
		'%' . $wpdb->esc_like( '"administrator"' ) . '%'
	) );
	$add( __( 'Non-founder administrator accounts registered on or after disclosure', 'compromise-scanner-for-wp2shell' ), 'high', 25, (string) $new_admins, $new_admins > 0 );

	/* Deleted-admin ghosts. */
	$orphaned = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->usermeta} m LEFT JOIN {$wpdb->users} u ON u.ID=m.user_id WHERE u.ID IS NULL" );
	$add( __( 'Orphaned user metadata from deleted accounts', 'compromise-scanner-for-wp2shell' ), 'medium', 15, (string) $orphaned, $orphaned > 0 );
	$max_id = (int) $wpdb->get_var( "SELECT MAX(ID) FROM {$wpdb->users}" );
	$count  = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->users}" );
	$auto   = (int) $wpdb->get_var( $wpdb->prepare( "SELECT AUTO_INCREMENT FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=%s", $wpdb->users ) );
	$gap    = ( $max_id - $count ) + ( $auto > 0 ? max( 0, $auto - 1 - $max_id ) : 0 );
	// Two guards against environmental gaps: (1) on shared-user-table installs (multisite
	// networks, CUSTOM_USER_TABLE, platform hosts such as WordPress.com) IDs are allocated
	// platform-wide, so gaps carry no signal for this site; (2) the exploit's create-then-delete
	// leaves only a handful of missing IDs, so a gap that dwarfs the account count points to
	// imports, spam cleanup, or shared hosting rather than an attack.
	$shared_users = is_multisite() || defined( 'CUSTOM_USER_TABLE' );
	$plausible    = ! $shared_users && $gap > 0 && $gap <= 10 * max( 10, $count );
	if ( $shared_users ) {
		$gap_detail = __( 'Not evaluated: the user table is shared across sites (multisite or platform hosting), so ID gaps are expected here.', 'compromise-scanner-for-wp2shell' );
	} elseif ( $gap > 0 && ! $plausible ) {
		/* translators: 1: number of missing IDs, 2: user count. */
		$gap_detail = sprintf( __( '%1$d missing IDs vs %2$d accounts — far too large for create-then-delete; typical of platform hosting, imports, or bulk cleanup, so not counted.', 'compromise-scanner-for-wp2shell' ), $gap, $count );
	} elseif ( $gap > 0 ) {
		/* translators: 1: number of missing IDs, 2: AUTO_INCREMENT value, 3: highest user ID, 4: user count. */
		$gap_detail = sprintf( __( '%1$d missing (auto_increment %2$d, max ID %3$d, %4$d accounts)', 'compromise-scanner-for-wp2shell' ), $gap, $auto, $max_id, $count );
	} else {
		$gap_detail = '';
	}
	// Weak on its own (legitimate user deletions and imports also leave gaps), so it carries
	// little weight and only corroborates stronger indicators.
	$add( __( 'Gap in user IDs, consistent with create-then-delete', 'compromise-scanner-for-wp2shell' ), 'low', 5, $gap_detail, $plausible );

	/* Webshell plugin directories or loose files. */
	$shells = array();
	if ( defined( 'WP_PLUGIN_DIR' ) ) {
		$shells = array_merge(
			(array) glob( WP_PLUGIN_DIR . '/wp2shell_*', GLOB_ONLYDIR ),
			(array) glob( WP_PLUGIN_DIR . '/wp2shell_*.php' )
		);
	}
	$add( __( 'Webshell plugin files or directories (wp2shell_*)', 'compromise-scanner-for-wp2shell' ), 'critical', 30, $shells ? implode( ', ', array_map( 'basename', $shells ) ) : '', ! empty( $shells ) );
	// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching

	if ( $result['score'] >= 50 ) {
		$result['verdict'] = 'compromised';
	} elseif ( $result['score'] >= 25 ) {
		$result['verdict'] = 'review';
	} else {
		$result['verdict'] = 'clean';
	}

	update_option( WP2SHELL_SCAN_OPTION, $result, false );
	return $result;
}

/**
 * Presentation metadata for a verdict.
 *
 * @param string $verdict Verdict key.
 * @return array
 */
function wp2shell_scan_verdict_meta( $verdict ) {
	$map = array(
		'compromised' => array(
			'label' => __( 'Multiple indicators matched', 'compromise-scanner-for-wp2shell' ),
			'badge' => __( 'Multiple indicators', 'compromise-scanner-for-wp2shell' ),
			'color' => '#b32d2e',
			'note'  => __( 'Several checks matched. This is worth looking into, but it is not confirmation of a breach on its own — the same artifacts can have legitimate causes. Go through the matched checks below with your webmaster before taking any action.', 'compromise-scanner-for-wp2shell' ),
		),
		'review'      => array(
			'label' => __( 'Some indicators matched', 'compromise-scanner-for-wp2shell' ),
			'badge' => __( 'Some indicators', 'compromise-scanner-for-wp2shell' ),
			'color' => '#bd8600',
			'note'  => __( 'A few checks matched. Individually these often have ordinary explanations — for example recent embeds, a newly added administrator, or a routine user deletion. This is not evidence of a breach on its own.', 'compromise-scanner-for-wp2shell' ),
		),
		'clean'       => array(
			'label' => __( 'No indicators matched', 'compromise-scanner-for-wp2shell' ),
			'badge' => __( 'No indicators', 'compromise-scanner-for-wp2shell' ),
			'color' => '#1a7f37',
			'note'  => __( 'None of the checks matched. This does not by itself prove the site is safe — a careful attacker can remove traces, and other attacks leave different evidence.', 'compromise-scanner-for-wp2shell' ),
		),
	);
	return isset( $map[ $verdict ] ) ? $map[ $verdict ] : $map['clean'];
}

/**
 * Presentation metadata for a severity level.
 *
 * @param string $severity Severity key.
 * @return array
 */
function wp2shell_scan_severity_meta( $severity ) {
	$map = array(
		'critical' => array( 'label' => __( 'Critical', 'compromise-scanner-for-wp2shell' ), 'color' => '#b32d2e' ),
		'high'     => array( 'label' => __( 'High', 'compromise-scanner-for-wp2shell' ), 'color' => '#d63638' ),
		'medium'   => array( 'label' => __( 'Medium', 'compromise-scanner-for-wp2shell' ), 'color' => '#bd8600' ),
		'low'      => array( 'label' => __( 'Low', 'compromise-scanner-for-wp2shell' ), 'color' => '#646970' ),
	);
	return isset( $map[ $severity ] ) ? $map[ $severity ] : $map['low'];
}

/**
 * Collect the actual database rows and file entries a human investigator needs to review.
 *
 * This is the point of the export: because the wp2shell chain smuggles its SQLi and the
 * pre-auth user creation inside a REST batch POST body — which web servers do not log — the
 * database artifacts are the primary evidence, not the access log. We hand over the raw rows
 * (read-only SELECTs, capped and excerpted) so an investigator can judge them directly.
 *
 * Privacy: only the *suspect* subset of users is exported (never the whole user table), and
 * password hashes and session tokens are never selected. Content columns are excerpted to
 * WP2SHELL_SCAN_EVIDENCE_MAX_CHARS and each table to WP2SHELL_SCAN_EVIDENCE_MAX_ROWS.
 *
 * @return array
 */
function wp2shell_scan_collect_evidence() {
	global $wpdb;
	// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Forensic evidence must be read live from the database; the export is user-initiated and never cached.
	$disclosure = WP2SHELL_SCAN_DISCLOSURE;
	$rows       = (int) WP2SHELL_SCAN_EVIDENCE_MAX_ROWS;
	$chars      = (int) WP2SHELL_SCAN_EVIDENCE_MAX_CHARS;
	$evidence   = array(
		'_about' => sprintf(
			/* translators: 1: max rows per table, 2: max characters per excerpt. */
			__( 'Read-only evidence for human review. Each table is capped at %1$d rows and content excerpts at %2$d characters. Password hashes and session tokens are never included. Only suspect users are listed, not the whole user table.', 'compromise-scanner-for-wp2shell' ),
			$rows,
			$chars
		),
	);

	// oembed_cache — the write primitive the chain abuses; content can hold the forged payload.
	$evidence['oembed_cache'] = $wpdb->get_results( $wpdb->prepare(
		"SELECT ID, post_author, post_date, post_date_gmt, post_status, post_title, post_name, guid, LEFT(post_content, %d) AS post_content_excerpt
		 FROM {$wpdb->posts} WHERE post_type='oembed_cache' ORDER BY post_date DESC LIMIT %d",
		$chars,
		$rows
	), ARRAY_A );

	// customize_changeset — the chain recasts the forged post into one of these.
	$evidence['customize_changeset'] = $wpdb->get_results( $wpdb->prepare(
		"SELECT ID, post_author, post_date, post_date_gmt, post_status, post_parent, post_title, post_name, LEFT(post_content, %d) AS post_content_excerpt
		 FROM {$wpdb->posts} WHERE post_type='customize_changeset' ORDER BY post_date DESC LIMIT %d",
		$chars,
		$rows
	), ARRAY_A );

	// Object-graph poisoning: implausible parent IDs or known PoC titles/slugs.
	$evidence['suspect_posts'] = $wpdb->get_results( $wpdb->prepare(
		"SELECT ID, post_type, post_author, post_date, post_status, post_parent, post_title, post_name
		 FROM {$wpdb->posts}
		 WHERE ( post_type IN ('customize_changeset','nav_menu_item','request') AND post_parent >= 1000000 )
		    OR ( post_type IN ('customize_changeset','nav_menu_item','request','oembed_cache')
		         AND ( post_title IN ('trigger','nav','parse','changeset','seed') OR post_name IN ('trigger','nav','parse','changeset','seed') ) )
		 ORDER BY ID DESC LIMIT %d",
		$rows
	), ARRAY_A );

	// Suspect users only: exploit-default login/email, or any administrator registered since
	// disclosure. Never user_pass. Roles pulled from the capabilities meta for context.
	$cap_key = $wpdb->get_blog_prefix() . 'capabilities';
	$evidence['suspect_users'] = $wpdb->get_results( $wpdb->prepare(
		"SELECT u.ID, u.user_login, u.user_email, u.user_registered, u.user_status,
		        (SELECT m.meta_value FROM {$wpdb->usermeta} m WHERE m.user_id=u.ID AND m.meta_key=%s LIMIT 1) AS capabilities
		 FROM {$wpdb->users} u
		 WHERE u.user_login LIKE %s
		    OR u.user_email LIKE %s
		    OR ( u.user_registered >= %s AND EXISTS (
		            SELECT 1 FROM {$wpdb->usermeta} m2
		            WHERE m2.user_id=u.ID AND m2.meta_key=%s AND m2.meta_value LIKE %s ) )
		 ORDER BY u.user_registered DESC LIMIT %d",
		$cap_key,
		$wpdb->esc_like( 'wp2_' ) . '%',
		'%' . $wpdb->esc_like( '@wp2shell.invalid' ),
		$disclosure,
		$cap_key,
		'%' . $wpdb->esc_like( '"administrator"' ) . '%',
		$rows
	), ARRAY_A );

	// Orphaned usermeta left by deleted accounts — meta_value excerpted (may hold role/cap data).
	$evidence['orphaned_usermeta'] = $wpdb->get_results( $wpdb->prepare(
		"SELECT m.umeta_id, m.user_id, m.meta_key, LEFT(m.meta_value, %d) AS meta_value_excerpt
		 FROM {$wpdb->usermeta} m LEFT JOIN {$wpdb->users} u ON u.ID=m.user_id
		 WHERE u.ID IS NULL ORDER BY m.umeta_id DESC LIMIT %d",
		$chars,
		$rows
	), ARRAY_A );

	// User-ID accounting, so an investigator can see the create-then-delete gap directly.
	$evidence['user_id_accounting'] = array(
		'min_id'         => (int) $wpdb->get_var( "SELECT MIN(ID) FROM {$wpdb->users}" ),
		'max_id'         => (int) $wpdb->get_var( "SELECT MAX(ID) FROM {$wpdb->users}" ),
		'count'          => (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->users}" ),
		'auto_increment' => (int) $wpdb->get_var( $wpdb->prepare( "SELECT AUTO_INCREMENT FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=%s", $wpdb->users ) ),
		'shared_table'   => ( is_multisite() || defined( 'CUSTOM_USER_TABLE' ) ),
	);

	// Filesystem: webshell dirs/files, plus plugin files modified since disclosure (both truncated).
	$files    = array();
	$webshell = array();
	if ( defined( 'WP_PLUGIN_DIR' ) ) {
		$webshell = array_merge(
			(array) glob( WP_PLUGIN_DIR . '/wp2shell_*', GLOB_ONLYDIR ),
			(array) glob( WP_PLUGIN_DIR . '/wp2shell_*.php' )
		);
		$since = strtotime( $disclosure );
		foreach ( (array) glob( WP_PLUGIN_DIR . '/*/*.php' ) as $php ) {
			$mtime = @filemtime( $php ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- filemtime warns on a race; treat unreadable as no evidence.
			if ( $mtime && $mtime >= $since ) {
				$files[] = array(
					'path'      => str_replace( WP_PLUGIN_DIR . '/', '', $php ),
					'size'      => (int) @filesize( $php ), // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- as above.
					'mtime_gmt' => gmdate( 'Y-m-d H:i:s', $mtime ),
				);
				if ( count( $files ) >= $rows ) {
					break;
				}
			}
		}
	}
	$evidence['webshell_paths']            = array_map( 'strval', $webshell );
	$evidence['plugin_files_since_disclosure'] = $files;
	// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching

	return $evidence;
}

/**
 * Assemble everything the scan knows into one machine-readable export payload.
 *
 * @param array $result   Scan result from wp2shell_scan_scan().
 * @param array $vstatus  Version status from wp2shell_scan_version_status().
 * @param array $evidence Raw evidence rows from wp2shell_scan_collect_evidence().
 * @return array
 */
function wp2shell_scan_export_payload( $result, $vstatus, $evidence = array() ) {
	return array(
		'generator'      => 'compromise-scanner-for-wp2shell/' . WP2SHELL_SCAN_VERSION,
		'generated_utc'  => gmdate( 'Y-m-d\TH:i:s\Z' ),
		'site'           => home_url(),
		'wordpress'      => isset( $GLOBALS['wp_version'] ) ? (string) $GLOBALS['wp_version'] : '',
		'php'            => PHP_VERSION,
		'multisite'      => is_multisite(),
		'version_status' => $vstatus,
		'thresholds'     => array(
			'review'      => 25,
			'compromised' => 50,
		),
		'scan'           => $result,
		'evidence'       => $evidence,
	);
}

/**
 * Render the export payload as a plain-text report (matched checks first).
 *
 * @param array $payload Export payload from wp2shell_scan_export_payload().
 * @return string
 */
function wp2shell_scan_export_text( $payload ) {
	$scan    = $payload['scan'];
	$verdict = isset( $scan['verdict'] ) ? $scan['verdict'] : 'clean';
	$vmeta   = wp2shell_scan_verdict_meta( $verdict );
	$order   = array( 'critical' => 0, 'high' => 1, 'medium' => 2, 'low' => 3 );
	$items   = isset( $scan['items'] ) ? $scan['items'] : array();
	usort( $items, function ( $a, $b ) use ( $order ) {
		if ( $a['hit'] !== $b['hit'] ) {
			return $a['hit'] ? -1 : 1;
		}
		$oa = isset( $order[ $a['severity'] ] ) ? $order[ $a['severity'] ] : 9;
		$ob = isset( $order[ $b['severity'] ] ) ? $order[ $b['severity'] ] : 9;
		return $oa <=> $ob;
	} );

	$lines   = array();
	$lines[] = 'Compromise Scanner for wp2shell - forensic scan report';
	$lines[] = str_repeat( '=', 54 );
	$lines[] = 'Generated (UTC): ' . $payload['generated_utc'];
	$lines[] = 'Site:            ' . $payload['site'];
	$lines[] = 'WordPress:       ' . $payload['wordpress'] . ' (version status: ' . $payload['version_status']['status'] . ')';
	$lines[] = 'PHP:             ' . $payload['php'];
	$lines[] = 'Plugin:          ' . WP2SHELL_SCAN_VERSION;
	$lines[] = 'Scan ran (UTC):  ' . ( isset( $scan['ran'] ) ? gmdate( 'Y-m-d H:i:s', (int) $scan['ran'] ) : '-' );
	$lines[] = 'Verdict:         ' . $vmeta['badge'];
	$lines[] = 'Score:           ' . ( isset( $scan['score'] ) ? (int) $scan['score'] : 0 ) . ' (Some indicators at 25, Multiple indicators at 50)';
	$lines[] = '';
	$lines[] = 'Findings (matched first):';
	foreach ( $items as $item ) {
		$lines[] = sprintf(
			'[%s] %-8s %2d pts  %s%s',
			$item['hit'] ? 'MATCHED' : '  --   ',
			strtoupper( $item['severity'] ),
			(int) $item['points'],
			$item['label'],
			'' !== $item['detail'] ? ' -- ' . $item['detail'] : ''
		);
	}
	if ( ! empty( $payload['evidence'] ) ) {
		$ev      = $payload['evidence'];
		$counts  = array(
			'oembed_cache'                  => 'oembed_cache rows',
			'customize_changeset'           => 'customize_changeset rows',
			'suspect_posts'                 => 'suspect posts (high parent ID / PoC title)',
			'suspect_users'                 => 'suspect users (exploit login/email or new admin)',
			'orphaned_usermeta'             => 'orphaned usermeta rows',
			'webshell_paths'                => 'webshell paths (wp2shell_*)',
			'plugin_files_since_disclosure' => 'plugin .php files modified since disclosure',
		);
		$lines[] = '';
		$lines[] = 'Raw evidence collected for review (full rows in evidence/*.json and scan-report.json):';
		foreach ( $counts as $key => $label ) {
			if ( isset( $ev[ $key ] ) ) {
				$lines[] = sprintf( '  %-45s %d', $label, count( (array) $ev[ $key ] ) );
			}
		}
	}
	$lines[] = '';
	$lines[] = 'Matched checks are not proof of a breach: each can have an ordinary cause and must be';
	$lines[] = 'verified individually. An all-clear result is not a guarantee either. This report is';
	$lines[] = 'best-effort and does not replace a proper investigation. The database rows in this';
	$lines[] = 'archive are the primary evidence for this exploit; see LOG-COLLECTION-GUIDE.txt for the';
	$lines[] = 'server-side logs to gather alongside them (this plugin cannot read those itself).';
	return implode( "\n", $lines ) . "\n";
}

/**
 * A hosting-agnostic guide telling the operator which server-side logs to collect by hand.
 *
 * The wp2shell chain hides its SQLi and pre-auth user creation inside a REST batch POST body,
 * which web servers do not log — so the database rows this plugin exports are the primary
 * evidence. These logs corroborate them (source IP, timing, entrypoint) but live outside
 * WordPress, so the plugin cannot read them; this tells a human where to look on a real host.
 *
 * @param array $payload Export payload (for the disclosure/site context lines).
 * @return string
 */
function wp2shell_scan_log_guide( $payload ) {
	$disclosure = substr( WP2SHELL_SCAN_DISCLOSURE, 0, 10 );
	$g   = array();
	$g[] = 'wp2shell — server-side logs to collect (real-world hosting)';
	$g[] = str_repeat( '=', 60 );
	$g[] = 'Site: ' . $payload['site'] . '   Disclosure date: ' . $disclosure;
	$g[] = '';
	$g[] = 'Why: the exploit smuggles its SQL injection and the pre-auth admin creation inside a';
	$g[] = 'REST /batch/v1 POST body. Web servers log the URL but NOT the body, so those steps';
	$g[] = 'usually leave no access-log line. The database rows in this archive are therefore the';
	$g[] = 'primary evidence. Collect the logs below to corroborate source IP, timing and entrypoint.';
	$g[] = 'On managed/shared hosting you may need to ask the host for logs older than a few days,';
	$g[] = 'or logs may be rotated away — if a source only goes back a few days it cannot cover the';
	$g[] = 'disclosure date above, so "nothing found" there means nothing.';
	$g[] = '';
	$g[] = '1. WEB SERVER ACCESS LOG (highest-value request-level tell)';
	$g[] = '   Apache: /var/log/apache2/access.log (Debian/Ubuntu), /var/log/httpd/access_log (RHEL),';
	$g[] = '           or per-vhost logs; cPanel: /home/<user>/logs/ or /usr/local/apache/domlogs/<domain>.';
	$g[] = '   nginx:  /var/log/nginx/access.log or per-server-block access_log path.';
	$g[] = '   Managed (Kinsta/WP Engine/Flywheel/Pantheon): download from the host dashboard/CLI.';
	$g[] = '   Grep for the entrypoint and any webshell hits:';
	$g[] = '     grep -aE "rest_route=/batch/v1|/wp-json/batch/v1|/wp-content/plugins/wp2shell_" access.log';
	$g[] = '   Look for POSTs to those paths, non-browser user agents (python-requests, curl, Go-http),';
	$g[] = '   and request bursts from one IP around the dates of the database rows in this archive.';
	$g[] = '';
	$g[] = '2. WEB SERVER / PHP ERROR LOG (can contain the full injected query if the SQLi errored)';
	$g[] = '   Apache: /var/log/apache2/error.log or /var/log/httpd/error_log.';
	$g[] = '   PHP-FPM: pool error log (e.g. /var/log/php*-fpm.log) or the path in php.ini "error_log".';
	$g[] = '     grep -aE "WordPress database error|post_author NOT IN|UNION ALL SELECT|serve_batch_request" error.log';
	$g[] = '';
	$g[] = '3. WORDPRESS debug.log (only if WP_DEBUG_LOG was ON before the incident)';
	$g[] = '   wp-content/debug.log — would mirror the $wpdb error and oembed fetch warnings.';
	$g[] = '';
	$g[] = '4. WAF / CDN LOGS (Cloudflare, Sucuri, etc.) — often the ONLY place the POST body or a';
	$g[] = '   rule match (author__not_in / UNION) is retained, and the real client IP behind the CDN.';
	$g[] = '   Export from the WAF/CDN dashboard for the window around the disclosure date.';
	$g[] = '';
	$g[] = '5. SECURITY / AUDIT PLUGIN LOGS (Wordfence live traffic, WP Activity Log, Sucuri) —';
	$g[] = '   the application layer that CAN record the user creation and the admin login that the';
	$g[] = '   raw access log misses. Check for a new administrator and its first login.';
	$g[] = '';
	$g[] = '6. MAIL LOG — WordPress emails the admin on new-user registration; a delivered/queued';
	$g[] = '   "New User Registration" mail near the incident corroborates the forged account.';
	$g[] = '   /var/log/mail.log, /var/log/maillog, or the host mail dashboard.';
	$g[] = '';
	$g[] = '7. FILE INTEGRITY — compare against a known-good backup and list recently changed files:';
	$g[] = '     find wp-content -newermt "' . $disclosure . '" -name "*.php" -printf "%TY-%Tm-%Td %TH:%TM %p\\n"';
	$g[] = '   (This plugin already lists plugin-dir changes it can see in evidence/filesystem.json.)';
	$g[] = '';
	$g[] = 'Handle these logs as potential evidence: copy them read-only, preserve timestamps, and';
	$g[] = 'involve a security professional before remediating. This guide is a starting point, not a';
	$g[] = 'complete incident-response procedure.';
	return implode( "\n", $g ) . "\n";
}

/**
 * Handle the "Export report" action (nonce-protected): stream the current scan result and the
 * raw forensic evidence as a zip archive, or as a single JSON payload when ZipArchive is
 * unavailable. The zip is built in a wp_tempnam() temp file that is deleted in the same request
 * — the export only reads site data, never writes it.
 *
 * Zip layout:
 *   scan-report.json                     full machine-readable payload (summary + evidence)
 *   scan-report.txt                      human-readable summary
 *   LOG-COLLECTION-GUIDE.txt             which server-side logs to gather by hand
 *   evidence/<table>.json                each raw evidence set, split out for review
 */
add_action( 'admin_post_wp2shell_scan_export', function () {
	if ( ! current_user_can( 'manage_options' ) ) {
		wp_die( esc_html__( 'You do not have permission to export this report.', 'compromise-scanner-for-wp2shell' ) );
	}
	check_admin_referer( 'wp2shell_scan_export' );

	$evidence = wp2shell_scan_collect_evidence();
	$payload  = wp2shell_scan_export_payload( wp2shell_scan_scan( false ), wp2shell_scan_version_status(), $evidence );
	$json     = (string) wp_json_encode( $payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES );
	$host     = (string) wp_parse_url( home_url(), PHP_URL_HOST );
	$base     = sanitize_file_name( 'wp2shell-scan-report_' . $host . '_' . gmdate( 'Ymd-His' ) );

	nocache_headers();

	if ( class_exists( 'ZipArchive' ) ) {
		if ( ! function_exists( 'wp_tempnam' ) || ! function_exists( 'WP_Filesystem' ) ) {
			require_once ABSPATH . 'wp-admin/includes/file.php';
		}
		$tmp = wp_tempnam( $base );
		$zip = new ZipArchive();
		if ( $tmp && true === $zip->open( $tmp, ZipArchive::OVERWRITE ) ) {
			$zip->addFromString( $base . '/scan-report.json', $json );
			$zip->addFromString( $base . '/scan-report.txt', wp2shell_scan_export_text( $payload ) );
			$zip->addFromString( $base . '/LOG-COLLECTION-GUIDE.txt', wp2shell_scan_log_guide( $payload ) );
			foreach ( $evidence as $name => $set ) {
				if ( '_about' === $name ) {
					continue;
				}
				$zip->addFromString(
					$base . '/evidence/' . sanitize_file_name( $name ) . '.json',
					(string) wp_json_encode( $set, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES )
				);
			}
			$zip->close();
			WP_Filesystem();
			global $wp_filesystem;
			$data = $wp_filesystem ? $wp_filesystem->get_contents( $tmp ) : false;
			wp_delete_file( $tmp );
			if ( false !== $data && '' !== $data ) {
				header( 'Content-Type: application/zip' );
				header( 'Content-Disposition: attachment; filename="' . $base . '.zip"' );
				header( 'Content-Length: ' . strlen( $data ) );
				echo $data; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Binary zip payload for a file download; escaping would corrupt it.
				exit;
			}
		} elseif ( $tmp ) {
			wp_delete_file( $tmp );
		}
	}

	// Fallback: ZipArchive missing or the archive could not be written — serve the JSON directly.
	header( 'Content-Type: application/json; charset=utf-8' );
	header( 'Content-Disposition: attachment; filename="' . $base . '.json"' );
	echo $json; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- JSON file download produced by wp_json_encode(); escaping would corrupt it.
	exit;
} );

/**
 * Register the admin menu entry.
 */
add_action( 'admin_menu', function () {
	$hook = add_menu_page(
		__( 'Compromise Scanner for wp2shell', 'compromise-scanner-for-wp2shell' ),
		__( 'wp2shell Scanner', 'compromise-scanner-for-wp2shell' ),
		'manage_options',
		WP2SHELL_SCAN_SLUG,
		'wp2shell_scan_render_page',
		'dashicons-shield',
		81
	);
	// Run the first scan lazily when the page is opened, not on every admin load.
	add_action( 'load-' . $hook, function () {
		if ( false === get_option( WP2SHELL_SCAN_OPTION ) ) {
			wp2shell_scan_scan( true );
		}
	} );
} );

/**
 * Handle the "Run scan" action (nonce-protected).
 */
add_action( 'admin_post_wp2shell_scan_rescan', function () {
	if ( ! current_user_can( 'manage_options' ) ) {
		wp_die( esc_html__( 'You do not have permission to run this scan.', 'compromise-scanner-for-wp2shell' ) );
	}
	check_admin_referer( 'wp2shell_scan_rescan' );
	wp2shell_scan_scan( true );
	wp_safe_redirect( add_query_arg(
		array( 'page' => WP2SHELL_SCAN_SLUG, 'scanned' => '1' ),
		admin_url( 'admin.php' )
	) );
	exit;
} );

/**
 * Handle the self-destruct action (deactivate and delete this plugin's files).
 */
add_action( 'admin_post_wp2shell_scan_selfdestruct', function () {
	if ( ! current_user_can( 'manage_options' ) ) {
		wp_die( esc_html__( 'You do not have permission to remove this plugin.', 'compromise-scanner-for-wp2shell' ) );
	}
	check_admin_referer( 'wp2shell_scan_selfdestruct' );
	delete_option( WP2SHELL_SCAN_OPTION );

	if ( ! function_exists( 'deactivate_plugins' ) ) {
		require_once ABSPATH . 'wp-admin/includes/plugin.php';
	}
	deactivate_plugins( plugin_basename( __FILE__ ) );

	if ( ! function_exists( 'WP_Filesystem' ) ) {
		require_once ABSPATH . 'wp-admin/includes/file.php';
	}
	WP_Filesystem();
	global $wp_filesystem;
	$dir        = dirname( __FILE__ );
	$in_plugins = defined( 'WP_PLUGIN_DIR' ) && 0 === strpos( $dir, WP_PLUGIN_DIR ) && $dir !== WP_PLUGIN_DIR;
	if ( $wp_filesystem && $in_plugins ) {
		$removed = $wp_filesystem->delete( $dir, true );
	} elseif ( $wp_filesystem ) {
		$removed = $wp_filesystem->delete( __FILE__ );
	} else {
		$removed = false;
	}
	wp_safe_redirect( add_query_arg( 'wp2shell_scan_removed', $removed ? '1' : '0', admin_url() ) );
	exit;
} );

/**
 * Surface a single, actionable admin notice only when the last scan found compromise
 * indicators. Routine "clean"/"review" states stay on the scanner screen.
 */
add_action( 'admin_notices', function () {
	if ( ! current_user_can( 'manage_options' ) ) {
		return;
	}
	$screen = get_current_screen();
	if ( $screen && false !== strpos( (string) $screen->id, WP2SHELL_SCAN_SLUG ) ) {
		return; // Don't duplicate the banner on our own page.
	}
	$result = get_option( WP2SHELL_SCAN_OPTION );
	if ( ! is_array( $result ) || empty( $result['verdict'] ) || 'compromised' !== $result['verdict'] ) {
		return;
	}
	printf(
		'<div class="notice notice-warning"><p><strong>%1$s</strong> %2$s <a href="%3$s">%4$s</a></p></div>',
		esc_html__( 'Compromise Scanner for wp2shell:', 'compromise-scanner-for-wp2shell' ),
		esc_html__( 'the last scan matched several checks. This is not confirmation of a breach — please review them.', 'compromise-scanner-for-wp2shell' ),
		esc_url( admin_url( 'admin.php?page=' . WP2SHELL_SCAN_SLUG ) ),
		esc_html__( 'Open the report', 'compromise-scanner-for-wp2shell' )
	);
} );

/**
 * Render the scanner screen.
 */
function wp2shell_scan_render_page() {
	if ( ! current_user_can( 'manage_options' ) ) {
		return;
	}
	$result       = wp2shell_scan_scan( false );
	$verdict      = isset( $result['verdict'] ) ? $result['verdict'] : 'clean';
	$vmeta        = wp2shell_scan_verdict_meta( $verdict );
	$score        = isset( $result['score'] ) ? (int) $result['score'] : 0;
	$ran          = isset( $result['ran'] ) ? (int) $result['ran'] : 0;
	$core_version = isset( $result['version'] ) ? $result['version'] : '';
	$vstatus      = wp2shell_scan_version_status();
	$affected     = ! empty( $vstatus['affected'] );
	$vstatus_meta = array(
		'vulnerable' => array( 'label' => __( 'Vulnerable', 'compromise-scanner-for-wp2shell' ), 'color' => '#b32d2e' ),
		'patched'    => array( 'label' => __( 'Patched', 'compromise-scanner-for-wp2shell' ), 'color' => '#1a7f37' ),
		'unknown'    => array( 'label' => __( 'Unknown', 'compromise-scanner-for-wp2shell' ), 'color' => '#646970' ),
	);
	$vm = isset( $vstatus_meta[ $vstatus['status'] ] ) ? $vstatus_meta[ $vstatus['status'] ] : $vstatus_meta['unknown'];

	// Order findings: matched first, then by severity weight.
	$order = array( 'critical' => 0, 'high' => 1, 'medium' => 2, 'low' => 3 );
	$items = isset( $result['items'] ) ? $result['items'] : array();
	usort( $items, function ( $a, $b ) use ( $order ) {
		if ( $a['hit'] !== $b['hit'] ) {
			return $a['hit'] ? -1 : 1;
		}
		$oa = isset( $order[ $a['severity'] ] ) ? $order[ $a['severity'] ] : 9;
		$ob = isset( $order[ $b['severity'] ] ) ? $order[ $b['severity'] ] : 9;
		return $oa <=> $ob;
	} );
	$matched = count( array_filter( $items, function ( $i ) {
		return $i['hit'];
	} ) );

	$rescan_url = wp_nonce_url( admin_url( 'admin-post.php?action=wp2shell_scan_rescan' ), 'wp2shell_scan_rescan' );
	$export_url = wp_nonce_url( admin_url( 'admin-post.php?action=wp2shell_scan_export' ), 'wp2shell_scan_export' );
	?>
	<div class="wrap">
		<h1 style="display:flex;align-items:center;gap:8px">
			<span class="dashicons dashicons-shield" style="color:#2271b1;font-size:26px;width:26px;height:26px"></span>
			<?php echo esc_html__( 'Compromise Scanner for wp2shell', 'compromise-scanner-for-wp2shell' ); ?>
			<span style="font-size:12px;color:#646970;font-weight:400">v<?php echo esc_html( WP2SHELL_SCAN_VERSION ); ?></span>
		</h1>
		<p style="max-width:64em;color:#3c434a">
			<?php echo esc_html__( 'A read-only check for known traces of the WordPress core wp2shell exploit chain (CVE-2026-63030 and CVE-2026-60137). It inspects the database and plugin directory and shows which checks matched. It does not modify the site and does not mitigate the vulnerability. Matched checks are not proof of a breach — see "What to do next" below.', 'compromise-scanner-for-wp2shell' ); ?>
		</p>

		<?php if ( isset( $_GET['scanned'] ) ) : // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only display flag after a nonce-verified redirect; no state is changed here. ?>
			<div class="notice notice-success is-dismissible"><p><?php echo esc_html__( 'Scan complete.', 'compromise-scanner-for-wp2shell' ); ?></p></div>
		<?php endif; ?>

		<div class="card" style="max-width:none;border-left:6px solid <?php echo esc_attr( $vmeta['color'] ); ?>;padding:16px 20px;margin-top:16px">
			<div style="display:flex;flex-wrap:wrap;align-items:center;gap:24px">
				<div>
					<div style="font-size:11px;text-transform:uppercase;letter-spacing:.5px;color:#646970"><?php echo esc_html__( 'Version status', 'compromise-scanner-for-wp2shell' ); ?></div>
					<div style="font-size:20px;font-weight:600;color:<?php echo esc_attr( $vm['color'] ); ?>"><?php echo esc_html( $vm['label'] ); ?> <span style="font-size:12px;font-weight:400;color:#646970"><?php echo esc_html( 'WP ' . $core_version ); ?></span></div>
				</div>
				<div>
					<div style="font-size:11px;text-transform:uppercase;letter-spacing:.5px;color:#646970"><?php echo esc_html__( 'Forensic verdict', 'compromise-scanner-for-wp2shell' ); ?></div>
					<div style="font-size:20px;font-weight:600;color:<?php echo esc_attr( $vmeta['color'] ); ?>"><?php echo esc_html( $vmeta['badge'] ); ?></div>
				</div>
				<div>
					<div style="font-size:11px;text-transform:uppercase;letter-spacing:.5px;color:#646970"><?php echo esc_html__( 'Forensic score', 'compromise-scanner-for-wp2shell' ); ?></div>
					<div style="font-size:20px;font-weight:600"><?php echo esc_html( (string) $score ); ?> <span style="font-size:12px;font-weight:400;color:#646970"><?php echo esc_html__( '(review at 25, compromised at 50)', 'compromise-scanner-for-wp2shell' ); ?></span></div>
				</div>
				<div>
					<div style="font-size:11px;text-transform:uppercase;letter-spacing:.5px;color:#646970"><?php echo esc_html__( 'Indicators matched', 'compromise-scanner-for-wp2shell' ); ?></div>
					<div style="font-size:20px;font-weight:600"><?php echo esc_html( $matched . ' / ' . count( $items ) ); ?></div>
				</div>
				<div>
					<div style="font-size:11px;text-transform:uppercase;letter-spacing:.5px;color:#646970"><?php echo esc_html__( 'Last scan', 'compromise-scanner-for-wp2shell' ); ?></div>
					<div style="font-size:14px;padding-top:4px"><?php echo $ran ? esc_html( wp_date( 'Y-m-d H:i', $ran ) ) : esc_html__( 'never', 'compromise-scanner-for-wp2shell' ); ?></div>
				</div>
				<div style="margin-left:auto;display:flex;gap:8px;align-items:center">
					<a href="<?php echo esc_url( $export_url ); ?>" class="button" title="<?php echo esc_attr__( 'Download a zip with the report (JSON + text), the raw database rows an investigator needs to review, and a guide to the server logs to collect. Nothing is stored on the site.', 'compromise-scanner-for-wp2shell' ); ?>"><?php echo esc_html__( 'Export report (.zip)', 'compromise-scanner-for-wp2shell' ); ?></a>
					<a href="<?php echo esc_url( $rescan_url ); ?>" class="button button-primary"><?php echo esc_html__( 'Run scan', 'compromise-scanner-for-wp2shell' ); ?></a>
				</div>
			</div>
			<p style="margin:12px 0 0;color:#3c434a"><?php echo esc_html( $vmeta['note'] ); ?></p>
		</div>

		<?php if ( 'vulnerable' === $vstatus['status'] ) : ?>
			<div class="notice notice-error inline" style="margin:16px 0"><p>
				<?php echo esc_html( sprintf(
					/* translators: %s: WordPress core version. */
					__( 'This site runs WordPress %s, which is missing the wp2shell fix, so it is currently exploitable regardless of the forensic result below. Update core to 6.8.6 / 6.9.5 / 7.0.2 (or later); this scanner does not mitigate.', 'compromise-scanner-for-wp2shell' ),
					$core_version
				) ); ?>
			</p></div>
		<?php elseif ( 'patched' === $vstatus['status'] ) : ?>
			<div class="notice notice-success inline" style="margin:16px 0"><p>
				<?php echo esc_html( sprintf(
					/* translators: %s: WordPress core version. */
					__( 'This site runs WordPress %s, which contains the wp2shell fix. Version status is separate from the forensic result below: being patched now does not rule out an exploit that occurred before the update.', 'compromise-scanner-for-wp2shell' ),
					$core_version
				) ); ?>
			</p></div>
		<?php else : ?>
			<div class="notice notice-warning inline" style="margin:16px 0"><p>
				<?php echo esc_html( sprintf(
					/* translators: %s: WordPress core version. */
					__( 'Could not classify WordPress %s against the affected range. If this is an old or custom build, update to a current release to be safe.', 'compromise-scanner-for-wp2shell' ),
					$core_version
				) ); ?>
			</p></div>
		<?php endif; ?>

		<h2 style="margin-top:24px"><?php echo esc_html__( 'Findings', 'compromise-scanner-for-wp2shell' ); ?></h2>
		<table class="widefat striped">
			<thead>
				<tr>
					<th style="width:90px"><?php echo esc_html__( 'Severity', 'compromise-scanner-for-wp2shell' ); ?></th>
					<th><?php echo esc_html__( 'Indicator', 'compromise-scanner-for-wp2shell' ); ?></th>
					<th style="width:120px"><?php echo esc_html__( 'Result', 'compromise-scanner-for-wp2shell' ); ?></th>
					<th style="width:34%"><?php echo esc_html__( 'Detail', 'compromise-scanner-for-wp2shell' ); ?></th>
				</tr>
			</thead>
			<tbody>
			<?php foreach ( $items as $item ) : ?>
				<?php $smeta = wp2shell_scan_severity_meta( $item['severity'] ); ?>
				<tr>
					<td>
						<span style="display:inline-block;padding:2px 8px;border-radius:3px;font-size:11px;font-weight:600;color:#fff;background:<?php echo esc_attr( $smeta['color'] ); ?>">
							<?php echo esc_html( $smeta['label'] ); ?>
						</span>
					</td>
					<td><?php echo esc_html( $item['label'] ); ?></td>
					<td>
						<?php if ( $item['hit'] ) : ?>
							<span style="color:#b32d2e;font-weight:600"><?php echo esc_html__( 'Matched', 'compromise-scanner-for-wp2shell' ); ?></span>
						<?php else : ?>
							<span style="color:#1a7f37"><?php echo esc_html__( 'Not matched', 'compromise-scanner-for-wp2shell' ); ?></span>
						<?php endif; ?>
					</td>
					<td style="color:#50575e"><?php echo '' !== $item['detail'] ? esc_html( $item['detail'] ) : '&mdash;'; ?></td>
				</tr>
			<?php endforeach; ?>
			</tbody>
		</table>

		<h2 style="margin-top:24px"><?php echo esc_html__( 'What to do next', 'compromise-scanner-for-wp2shell' ); ?></h2>
		<?php if ( 'clean' === $verdict ) : ?>
			<ul style="list-style:disc;margin-left:20px;max-width:64em;color:#3c434a">
				<li><?php echo esc_html__( 'No checks matched. Keep WordPress core updated and re-run this scan occasionally.', 'compromise-scanner-for-wp2shell' ); ?></li>
				<li><?php echo esc_html__( 'If the version status above is "Vulnerable", update core to a fixed version (6.8.6 / 6.9.5 / 7.0.2 or later).', 'compromise-scanner-for-wp2shell' ); ?></li>
			</ul>
		<?php else : ?>
			<p style="max-width:64em;color:#3c434a"><?php echo esc_html__( 'Some checks matched. Please read this before doing anything — the steps are in order of least to most disruptive:', 'compromise-scanner-for-wp2shell' ); ?></p>
			<ol style="margin-left:20px;max-width:64em;color:#3c434a;line-height:1.7">
				<li><?php echo esc_html__( 'Do not act on this quick check alone. It looks for known traces of one specific exploit and can report matches that turn out to be harmless.', 'compromise-scanner-for-wp2shell' ); ?></li>
				<li><?php echo esc_html__( 'Go through the matched checks above and ask your webmaster or hosting provider whether each has a known, legitimate explanation (for example a recent embed, a newly added administrator, or a deleted account).', 'compromise-scanner-for-wp2shell' ); ?></li>
				<li><?php echo esc_html__( 'If something cannot be explained, consider a proper investigation: review server and access logs, check file integrity, and involve a security professional.', 'compromise-scanner-for-wp2shell' ); ?></li>
				<li><?php echo esc_html__( 'Restoring from a known-good backup or reinstalling WordPress is a last resort. Consider it only after the steps above — never on the basis of this quick check alone.', 'compromise-scanner-for-wp2shell' ); ?></li>
				<li><?php echo esc_html__( 'Separately, if the version status above is "Vulnerable", update core to a fixed version (6.8.6 / 6.9.5 / 7.0.2 or later).', 'compromise-scanner-for-wp2shell' ); ?></li>
			</ol>
		<?php endif; ?>

		<h2 style="margin-top:24px"><?php echo esc_html__( 'About this scan', 'compromise-scanner-for-wp2shell' ); ?></h2>
		<p style="max-width:64em;font-size:13px;color:#646970">
			<?php echo esc_html__( 'This is a quick, read-only check. It reports which of a fixed list of checks matched — nothing more. Matched checks are not proof of a breach: each can have an ordinary cause, so verify them individually. An all-clear result is not a guarantee either, because a careful attacker can remove traces and other attacks leave different evidence. It does not replace keeping core updated or a proper investigation.', 'compromise-scanner-for-wp2shell' ); ?>
		</p>
		<p style="max-width:64em;font-size:12px;color:#8c8f94">
			<?php echo esc_html__( 'Provided "as is", without warranty of any kind. To the maximum extent permitted by law, the authors and distributors accept no liability for any damage, false positives, missed detections, or actions taken based on its output. You are responsible for verifying its results and for your authorization to run it.', 'compromise-scanner-for-wp2shell' ); ?>
		</p>

		<hr style="margin:24px 0">
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>"
			onsubmit="return confirm('<?php echo esc_js( __( 'Remove the Compromise Scanner for wp2shell plugin now?', 'compromise-scanner-for-wp2shell' ) ); ?>');">
			<input type="hidden" name="action" value="wp2shell_scan_selfdestruct">
			<?php wp_nonce_field( 'wp2shell_scan_selfdestruct' ); ?>
			<button type="submit" class="button button-secondary"><?php echo esc_html__( 'Remove this plugin', 'compromise-scanner-for-wp2shell' ); ?></button>
			<span style="font-size:12px;color:#8c8f94;margin-left:8px"><?php echo esc_html__( 'Deactivates and deletes the plugin files.', 'compromise-scanner-for-wp2shell' ); ?></span>
		</form>
	</div>
	<?php
}

/**
 * Confirmation notice after the plugin removes itself (shown once, on redirect).
 */
add_action( 'admin_notices', function () {
	if ( ! current_user_can( 'manage_options' ) || ! isset( $_GET['wp2shell_scan_removed'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only display flag after a nonce-verified redirect; no state is changed here.
		return;
	}
	$ok = '1' === sanitize_text_field( wp_unslash( $_GET['wp2shell_scan_removed'] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- See above.
	if ( $ok ) {
		echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__( 'Compromise Scanner for wp2shell removed itself successfully.', 'compromise-scanner-for-wp2shell' ) . '</p></div>';
	} else {
		echo '<div class="notice notice-error is-dismissible"><p>' . esc_html__( 'Compromise Scanner for wp2shell could not delete its files. Remove wp-content/plugins/compromise-scanner-for-wp2shell/ manually.', 'compromise-scanner-for-wp2shell' ) . '</p></div>';
	}
} );
