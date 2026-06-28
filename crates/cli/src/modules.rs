use nevelio_core::AttackModule;
use nevelio_module_access_control::AccessControlModule;
use nevelio_module_auth::AuthModule;
use nevelio_module_business_logic::BusinessLogicModule;
use nevelio_module_graphql::GraphqlModule;
use nevelio_module_grpc::GrpcModule;
use nevelio_module_infra::InfraModule;
use nevelio_module_injection::InjectionModule;
use nevelio_module_oauth2::OAuth2Module;
use nevelio_module_prototype_pollution::PrototypePollutionModule;
use nevelio_module_soap::SoapModule;
use nevelio_module_ssrf::SsrfModule;
use nevelio_module_websocket::WebSocketModule;

/// Build the canonical list of all attack modules.
/// Used by scan, watch, and shell commands.
pub fn build_all_modules() -> Vec<Box<dyn AttackModule>> {
    vec![
        Box::new(AuthModule),
        Box::new(InjectionModule),
        Box::new(AccessControlModule),
        Box::new(BusinessLogicModule),
        Box::new(GraphqlModule),
        Box::new(InfraModule),
        Box::new(SsrfModule),
        Box::new(OAuth2Module),
        Box::new(PrototypePollutionModule),
        Box::new(WebSocketModule),
        Box::new(SoapModule),
        Box::new(GrpcModule),
    ]
}
