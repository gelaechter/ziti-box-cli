# CaDetail

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**_links** | [**std::collections::HashMap<String, models::Link>**](link.md) | A map of named links | 
**created_at** | **String** |  | 
**id** | **String** |  | 
**tags** | Option<[**models::Tags**](tags.md)> |  | [optional]
**updated_at** | **String** |  | 
**cert_pem** | **String** |  | 
**external_id_claim** | Option<[**models::ExternalIdClaim**](externalIdClaim.md)> |  | [optional]
**fingerprint** | **String** |  | 
**identity_name_format** | **String** |  | 
**identity_roles** | **Vec<String>** |  | 
**is_auth_enabled** | **bool** |  | 
**is_auto_ca_enrollment_enabled** | **bool** |  | 
**is_ott_ca_enrollment_enabled** | **bool** |  | 
**is_verified** | **bool** |  | 
**name** | **String** |  | 
**verification_token** | Option<[**uuid::Uuid**](uuid::Uuid.md)> |  | [optional]

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


