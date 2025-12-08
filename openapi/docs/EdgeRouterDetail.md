# EdgeRouterDetail

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**_links** | [**std::collections::HashMap<String, models::Link>**](link.md) | A map of named links | 
**created_at** | **String** |  | 
**id** | **String** |  | 
**tags** | Option<[**models::Tags**](tags.md)> |  | [optional]
**updated_at** | **String** |  | 
**app_data** | Option<[**models::Tags**](tags.md)> |  | [optional]
**cost** | Option<**i32**> |  | 
**disabled** | **bool** |  | 
**hostname** | **String** |  | 
**is_online** | **bool** |  | 
**name** | **String** |  | 
**no_traversal** | Option<**bool**> |  | 
**supported_protocols** | **std::collections::HashMap<String, String>** |  | 
**sync_status** | **String** |  | 
**cert_pem** | Option<**String**> |  | [optional]
**enrollment_created_at** | Option<**String**> |  | [optional]
**enrollment_expires_at** | Option<**String**> |  | [optional]
**enrollment_jwt** | Option<**String**> |  | [optional]
**enrollment_token** | Option<**String**> |  | [optional]
**fingerprint** | Option<**String**> |  | [optional]
**interfaces** | Option<[**Vec<models::Interface>**](interface.md)> |  | [optional]
**is_tunneler_enabled** | **bool** |  | 
**is_verified** | **bool** |  | 
**role_attributes** | Option<**Vec<String>**> | A set of strings used to loosly couple this resource to policies | 
**unverified_cert_pem** | Option<**String**> |  | [optional]
**unverified_fingerprint** | Option<**String**> |  | [optional]
**version_info** | Option<[**models::VersionInfo**](versionInfo.md)> |  | [optional]

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


