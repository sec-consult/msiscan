
def analyze_standard_action(action, condition):
	uninteresing = [
		
	]
	unknown = [
		"ADMIN", "ADVERTISE", "AllocateRegistrySpace", "AppSearch", "BindImage", "CCPSearch", "CostFinalize", "CostInitialize", "CreateFolders", "CreateShortcuts", "DeleteServices", "DisableRollback", "DuplicateFiles", "ExecuteAction", "FileCost", "FindRelatedProducts", "ForceReboot", "INSTALL", "InstallAdminPackage", "InstallExecute", "InstallFiles", "InstallFinalize", "InstallInitialize", "InstallSFPCatalogFile", "InstallValidate", "IsolateComponents", "LaunchConditions", "MigrateFeatureStates", "MoveFiles", "MsiConfigureServices", "MsiPublishAssemblies action", "MsiUnpublishAssemblies", "InstallODBC", "InstallServices", "PatchFiles", "ProcessComponents", "PublishComponents", "PublishFeatures", "PublishProduct", "RegisterClassInfo", "RegisterComPlus", "RegisterExtensionInfo", "RegisterFonts", "RegisterMIMEInfo", "RegisterProduct", "RegisterProgIdInfo", "RegisterTypeLibraries", "RegisterUser", "RemoveDuplicateFiles", "RemoveEnvironmentStrings", "RemoveExistingProducts", "RemoveFiles", "RemoveFolders", "RemoveIniValues", "RemoveODBC", "RemoveRegistryValues", "RemoveShortcuts", "ResolveSource", "RMCCPSearch", "ScheduleReboot", "SelfRegModules", "SelfUnregModules", "SEQUENCE", "SetODBCFolders Action", "StartServices", "StopServices", "UnpublishComponents", "UnpublishFeatures", "UnregisterClassInfo", "UnregisterComPlus", "UnregisterExtensionInfo", "UnregisterFonts", "UnregisterMIMEInfo", "UnregisterProgIdInfo", "UnregisterTypeLibraries", "ValidateProductID", "WriteEnvironmentStrings", "WriteIniValues", "WriteRegistryValues"
	]
	if action in uninteresing:
		return None, None
	if action in unknown:
		return None, None
	if action == "PrepareDlg":
		return f"{action} {condition}", "white"
	return f"UNKNOWN ACTION: {action}", "white"
