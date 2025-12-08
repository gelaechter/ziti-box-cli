# IdentityUpdate

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**app_data** | Option<[**models::Tags**](tags.md)> |  | [optional]
**auth_policy_id** | Option<**String**> |  | [optional]
**default_hosting_cost** | Option<**i32**> |  | [optional]
**default_hosting_precedence** | Option<[**models::TerminatorPrecedence**](terminatorPrecedence.md)> |  | [optional]
**external_id** | Option<**String**> |  | [optional]
**is_admin** | **bool** |  | 
**name** | **String** |  | 
**role_attributes** | Option<**Vec<String>**> | A set of strings used to loosly couple this resource to policies | [optional]
**service_hosting_costs** | Option<**std::collections::HashMap<String, i32>**> |  | [optional]
**service_hosting_precedences** | Option<[**std::collections::HashMap<String, models::TerminatorPrecedence>**](terminatorPrecedence.md)> |  | [optional]
**tags** | Option<[**models::Tags**](tags.md)> |  | [optional]
**r#type** | [**models::IdentityType**](identityType.md) |  | 

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


