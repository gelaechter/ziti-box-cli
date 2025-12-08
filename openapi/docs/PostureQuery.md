# PostureQuery

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**_links** | [**std::collections::HashMap<String, models::Link>**](link.md) | A map of named links | 
**created_at** | **String** |  | 
**id** | **String** |  | 
**tags** | Option<[**models::Tags**](tags.md)> |  | [optional]
**updated_at** | **String** |  | 
**is_passing** | **bool** |  | 
**process** | Option<[**models::PostureQueryProcess**](postureQueryProcess.md)> |  | [optional]
**processes** | Option<[**Vec<models::PostureQueryProcess>**](postureQueryProcess.md)> |  | [optional]
**prompt_grace_period_seconds** | Option<**i32**> |  | [optional]
**prompt_on_unlock** | Option<**bool**> |  | [optional]
**prompt_on_wake** | Option<**bool**> |  | [optional]
**query_type** | [**models::PostureCheckType**](postureCheckType.md) |  | 
**timeout** | **i32** |  | 
**timeout_at** | Option<**String**> |  | [optional]
**timeout_remaining** | **i32** |  | 

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


