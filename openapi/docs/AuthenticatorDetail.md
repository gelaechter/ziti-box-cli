# AuthenticatorDetail

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**_links** | [**std::collections::HashMap<String, models::Link>**](link.md) | A map of named links | 
**created_at** | **String** |  | 
**id** | **String** |  | 
**tags** | Option<[**models::Tags**](tags.md)> |  | [optional]
**updated_at** | **String** |  | 
**cert_pem** | Option<**String**> |  | [optional]
**extend_requested_at** | Option<**String**> |  | [optional]
**fingerprint** | Option<**String**> |  | [optional]
**identity** | [**models::EntityRef**](entityRef.md) |  | 
**identity_id** | **String** |  | 
**is_extend_requested** | Option<**bool**> |  | [optional]
**is_issued_by_network** | Option<**bool**> |  | [optional]
**is_key_roll_requested** | Option<**bool**> |  | [optional]
**last_auth_resolved_to_root** | Option<**bool**> |  | [optional]
**last_extend_rolled_keys** | Option<**bool**> |  | [optional]
**method** | **String** |  | 
**username** | Option<**String**> |  | [optional]

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


