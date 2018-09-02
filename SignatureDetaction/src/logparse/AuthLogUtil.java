package logparse;

public class AuthLogUtil {
	// Alert Level
	protected enum Alert {
		SEVERE, WARNING, NOTICE, NONE
	}
	
	// Command execution rate for alert
	protected static double ALERT_SEVIRE = 0.85;
	protected static double ALERT_WARNING = 0.15;
	
}
