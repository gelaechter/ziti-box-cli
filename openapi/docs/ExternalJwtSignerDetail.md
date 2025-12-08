# ExternalJwtSignerDetail

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**_links** | [**std::collections::HashMap<String, models::Link>**](link.md) | A map of named links | 
**created_at** | **String** |  | 
**id** | **String** |  | 
**tags** | Option<[**models::Tags**](tags.md)> |  | [optional]
**updated_at** | **String** |  | 
**audience** | **String** |  | 
**cert_pem** | Option<**String**> |  | 
**claims_property** | **String** |  | 
**client_id** | **String** |  | 
**common_name** | **String** |  | 
**enabled** | **bool** |  | 
**enroll_attribute_claims_selector** | Option<**String**> |  | [optional]
**enroll_auth_policy_id** | Option<**String**> |  | [optional]
**enroll_name_claims_selector** | Option<**String**> |  | [optional]
**enroll_to_cert_enabled** | Option<**bool**> |  | [optional]
**enroll_to_token_enabled** | Option<**bool**> |  | [optional]
**external_auth_url** | **String** |  | 
**fingerprint** | **String** |  | 
**issuer** | **String** |  | 
**jwks_endpoint** | Option<**String**> |  | 
**kid** | **String** |  | 
**name** | **String** |  | 
**not_after** | **String** |  | 
**not_before** | **String** |  | 
**scopes** | **Vec<String>** |  | 
**target_token** | Option<[**models::TargetToken**](targetToken.md)> |  | 
**use_external_id** | **bool** |  | 

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


