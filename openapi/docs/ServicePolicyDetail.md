# ServicePolicyDetail

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**_links** | [**std::collections::HashMap<String, models::Link>**](link.md) | A map of named links | 
**created_at** | **String** |  | 
**id** | **String** |  | 
**tags** | Option<[**models::Tags**](tags.md)> |  | [optional]
**updated_at** | **String** |  | 
**identity_roles** | **Vec<String>** |  | 
**identity_roles_display** | [**Vec<models::NamedRole>**](namedRole.md) |  | 
**name** | **String** |  | 
**posture_check_roles** | **Vec<String>** |  | 
**posture_check_roles_display** | [**Vec<models::NamedRole>**](namedRole.md) |  | 
**semantic** | [**models::Semantic**](semantic.md) |  | 
**service_roles** | **Vec<String>** |  | 
**service_roles_display** | [**Vec<models::NamedRole>**](namedRole.md) |  | 
**r#type** | [**models::DialBind**](dialBind.md) |  | 

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


