# IdentityDetail

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**_links** | [**std::collections::HashMap<String, models::Link>**](link.md) | A map of named links | 
**created_at** | **String** |  | 
**id** | **String** |  | 
**tags** | Option<[**models::Tags**](tags.md)> |  | [optional]
**updated_at** | **String** |  | 
**app_data** | Option<[**models::Tags**](tags.md)> |  | [optional]
**auth_policy** | [**models::EntityRef**](entityRef.md) |  | 
**auth_policy_id** | **String** |  | 
**authenticators** | [**models::IdentityAuthenticators**](identityAuthenticators.md) |  | 
**default_hosting_cost** | **i32** |  | 
**default_hosting_precedence** | Option<[**models::TerminatorPrecedence**](terminatorPrecedence.md)> |  | [optional]
**disabled** | **bool** |  | 
**disabled_at** | Option<**String**> |  | [optional]
**disabled_until** | Option<**String**> |  | [optional]
**edge_router_connection_status** | **String** |  | 
**enrollment** | [**models::IdentityEnrollments**](identityEnrollments.md) |  | 
**env_info** | [**models::EnvInfo**](envInfo.md) |  | 
**external_id** | Option<**String**> |  | 
**has_api_session** | **bool** |  | 
**has_edge_router_connection** | **bool** |  | 
**interfaces** | Option<[**Vec<models::Interface>**](interface.md)> |  | [optional]
**is_admin** | **bool** |  | 
**is_default_admin** | **bool** |  | 
**is_mfa_enabled** | **bool** |  | 
**name** | **String** |  | 
**role_attributes** | Option<**Vec<String>**> | A set of strings used to loosly couple this resource to policies | 
**sdk_info** | [**models::SdkInfo**](sdkInfo.md) |  | 
**service_hosting_costs** | **std::collections::HashMap<String, i32>** |  | 
**service_hosting_precedences** | [**std::collections::HashMap<String, models::TerminatorPrecedence>**](terminatorPrecedence.md) |  | 
**r#type** | [**models::EntityRef**](entityRef.md) |  | 
**type_id** | **String** |  | 

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


