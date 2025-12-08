# DetailMfa

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**_links** | [**std::collections::HashMap<String, models::Link>**](link.md) | A map of named links | 
**created_at** | **String** |  | 
**id** | **String** |  | 
**tags** | Option<[**models::Tags**](tags.md)> |  | [optional]
**updated_at** | **String** |  | 
**is_verified** | **bool** |  | 
**provisioning_url** | Option<**String**> | Not provided if MFA verification has been completed | [optional]
**recovery_codes** | Option<**Vec<String>**> | Not provided if MFA verification has been completed | [optional]

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


