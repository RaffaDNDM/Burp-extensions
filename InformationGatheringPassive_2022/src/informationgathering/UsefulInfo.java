package informationgathering;

import java.util.Arrays;
import java.util.List;

public final class UsefulInfo {
		public static List<String> FINGERPRINTING_HEADERS = Arrays.asList("microsoftsharepointteamservices",
																		  "server",
																		  "via",
																		  "x-aspnet-version",
																		  "x-aspnetmvc-version",
																		  "x-powered-by",
																		  "$wsep");
		
		public static List<String> SECURITY_HEADERS = Arrays.asList("x-frame-options",
				"x-content-type-options",
				"strict-transport-security",
				"content-security-policy",
				"referrer-policy",
				"x-xss-protection",
				"expect-ct",
				"permissions-policy",
				"cross-origin-embedder-policy",
				"cross-origin-resource-policy",
				"cross-origin-opener-policy");
}
