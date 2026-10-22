/**
 * Product name, source links and operator contact in one place.
 *
 * InterCat Lynx is a fork of OpenThreat. The licence (AGPL-3.0) requires that
 * users of a network service can get the source code of the running version
 * and that the origin of the code stays visible, so both links are always
 * shown in the footer and on the About page.
 *
 * The operator contact is NOT hard-coded: whoever runs an instance is
 * responsible for the data processing (privacy policy) and sets it through
 * environment variables at build time.
 */

export const PRODUCT_NAME = "InterCat Lynx";
export const PRODUCT_TAGLINE = "Vulnerability intelligence";

/** Source of this fork (AGPL-3.0 §13: offer the source to network users). */
export const SOURCE_URL =
  process.env.NEXT_PUBLIC_SOURCE_URL || "https://github.com/mbr-crypt/intercat-lynx";

/** The project this fork is based on. */
export const UPSTREAM_NAME = "OpenThreat";
export const UPSTREAM_URL = "https://github.com/hoodinformatik/OpenThreat";

export const LICENSE_NAME = "GNU Affero General Public License v3.0";
export const LICENSE_URL = "https://www.gnu.org/licenses/agpl-3.0.html";

/** Who runs this instance (shown on the privacy page). Optional. */
export const OPERATOR_NAME = process.env.NEXT_PUBLIC_OPERATOR_NAME || "";
export const OPERATOR_EMAIL = process.env.NEXT_PUBLIC_CONTACT_EMAIL || "";

/**
 * Rights holder of the names and logos "Intercat" and "InterCat Lynx".
 * The source code is AGPL-3.0, the names and logos are NOT (see NOTICE).
 */
export const BRAND_OWNER = "Moritz Rehmann";
export const BRAND_SITE_URL = "https://intercat.it";
