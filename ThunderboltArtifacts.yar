rule ThunderboltServiceInstalledAndRunning {
	meta:
		description = "Identification of installed and running Thunderbolt service"
	strings:
		$lenovo = "\\Windows\\ThunderboltService.exe"
		$intel = "\\Windows\\TbtP2pShortcutService.exe"
	condition:
        $lenovo or $intel
}

rule ThunderboltControlAppRunning {
	meta:
		description = "Thunderbolt Control App started"
	strings:
		$tb_control_center = "ThunderboltControlApp.exe"
	condition:
        ThunderboltServiceInstalledAndRunning and $tb_control_center
}

rule BelkinThunderbolt3DockCoreConnected {
	meta:
		description = "Detects specific Thunderbolt device"
	strings:
		$device = "Thunderbolt 3 Dock Core"
	condition:
        $device
}

rule OWCEnvoyExpress {
	meta:
		description = "Detects specific Thunderbolt device"
	strings:
		$device = "Envoy Express TBT"
	condition:
        $device
}

rule IntelJHL6240Controller {
	meta:
		description = "Detects Intel JHL6240 Thunderbolt Controller"
	strings:
		$controller_model = "PCI\\VEN_8086&DEV_15C0"
	condition:
        $controller_model
}

rule IntelJHL6340Controller {
	meta:
		description = "Detects Intel JHL6340 Thunderbolt Controller"
	strings:
		$controller_model = "PCI\\VEN_8086&DEV_15DA"
	condition:
        $controller_model
}

rule IntelJHL7540Controller {
	meta:
		description = "Detects Intel JHL7540 Thunderbolt Controller"
	strings:
		$controller_model = "PCI\\VEN_8086&DEV_15EA"
	condition:
        $controller_model
}

rule ThunderboltHostController {
	meta:
		description = "Detects occurrance of non specific Thunderbolt Controller"
	strings:
		$controller = "ThunderboltHostController"
	condition:
        (not IntelJHL6240Controller) and (not IntelJHL6340Controller) and (not IntelJHL7540Controller) and $controller
}