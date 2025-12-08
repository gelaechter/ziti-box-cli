# ApiSessionDetail

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**_links** | [**std::collections::HashMap<String, models::Link>**](link.md) | A map of named links | 
**created_at** | **String** |  | 
**id** | **String** |  | 
**tags** | Option<[**models::Tags**](tags.md)> |  | [optional]
**updated_at** | **String** |  | 
**auth_queries** | [**Vec<models::AuthQueryDetail>**](authQueryDetail.md) |  | 
**authenticator_id** | **String** |  | 
**cached_last_activity_at** | Option<**String**> |  | [optional]
**config_types** | **Vec<String>** |  | 
**identity** | [**models::EntityRef**](entityRef.md) |  | 
**identity_id** | **String** |  | 
**improper_client_cert_chain** | Option<**bool**> |  | [optional]
**ip_address** | **String** |  | 
**is_cert_extend_requested** | Option<**bool**> |  | [optional]
**is_cert_extendable** | **bool** |  | 
**is_cert_key_roll_requested** | Option<**bool**> |  | [optional]
**is_mfa_complete** | **bool** |  | 
**is_mfa_required** | **bool** |  | 
**last_activity_at** | Option<**String**> |  | [optional]
**token** | **String** |  | 

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


