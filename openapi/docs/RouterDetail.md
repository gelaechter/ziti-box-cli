# RouterDetail

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**_links** | [**std::collections::HashMap<String, models::Link>**](link.md) | A map of named links | 
**created_at** | **String** |  | 
**id** | **String** |  | 
**tags** | Option<[**models::Tags**](tags.md)> |  | [optional]
**updated_at** | **String** |  | 
**cost** | **i32** |  | 
**disabled** | **bool** |  | 
**enrollment_created_at** | Option<**String**> |  | [optional]
**enrollment_expires_at** | Option<**String**> |  | [optional]
**enrollment_jwt** | Option<**String**> |  | [optional]
**enrollment_token** | Option<**String**> |  | [optional]
**fingerprint** | **String** |  | 
**interfaces** | Option<[**Vec<models::Interface>**](interface.md)> |  | [optional]
**is_online** | **bool** |  | 
**is_verified** | **bool** |  | 
**name** | **String** |  | 
**no_traversal** | **bool** |  | 
**unverified_cert_pem** | Option<**String**> |  | [optional]
**unverified_fingerprint** | Option<**String**> |  | [optional]

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


