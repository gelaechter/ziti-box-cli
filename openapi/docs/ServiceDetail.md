# ServiceDetail

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**_links** | [**std::collections::HashMap<String, models::Link>**](link.md) | A map of named links | 
**created_at** | **String** |  | 
**id** | **String** |  | 
**tags** | Option<[**models::Tags**](tags.md)> |  | [optional]
**updated_at** | **String** |  | 
**config** | [**std::collections::HashMap<String, std::collections::HashMap<String, serde_json::Value>>**](std::collections::HashMap.md) | map of config data for this service keyed by the config type name. Only configs of the types requested will be returned. | 
**configs** | **Vec<String>** |  | 
**encryption_required** | **bool** | Describes whether connections must support end-to-end encryption on both sides of the connection. Read-only property, set at create. | 
**max_idle_time_millis** | **i32** |  | 
**name** | **String** |  | 
**permissions** | [**Vec<models::DialBind>**](dialBind.md) |  | 
**posture_queries** | [**Vec<models::PostureQueries>**](postureQueries.md) |  | 
**role_attributes** | Option<**Vec<String>**> | A set of strings used to loosly couple this resource to policies | 
**terminator_strategy** | **String** |  | 

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


