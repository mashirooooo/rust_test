use axum::{
    body::{self, Body},
    http::{Request, StatusCode},
    response::{IntoResponse, Response},
    routing::get_service,
    Router,
};
use dotenv::dotenv;
use hyper::{upgrade::Upgraded, Method, Uri, HeaderMap};
use std::env;
use std::{io, net::SocketAddr};
use tokio::net::TcpStream;
use tower_http::{
    services::{ServeDir, ServeFile},
    trace::TraceLayer,
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
#[tokio::main]
async fn main() {

    dotenv().ok();
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new("info"))
        .with(tracing_subscriber::fmt::layer())
        .init();
    let port = env::var("PORT")
        .unwrap_or_else(|_| "3000".to_string())
        .parse()
        .unwrap();
    // let addr = SocketAddr::from(([0, 0, 0, 0], port));
    // 开启vue html
    let serve_dir =
        get_service(ServeDir::new("assets").not_found_service(ServeFile::new("assets/index.html")))
            .handle_error(handle_error);

    let proxy_service = tower::service_fn(move |mut req: Request<Body>| async move {
        tracing::info!("代理{req:#?}");
        // req.headers_mut()
        let headers = req.headers_mut();
        // 重写头部
        headers.insert("user-agent",  "Mozilla/5.0 (iPhone; CPU iPhone OS 10_3_1 like Mac OS X) AppleWebKit/603.1.3 (KHTML, like Gecko) Version/10.0 Mobile/14E304 Safari/602.1 wechatdevtools/1.06.2209190 MicroMessenger/8.0.5 Language/zh_CN webview/".parse().unwrap());
        headers.insert("host",  "www.baidu.com".parse().unwrap());
        headers.remove("referer");
        headers.remove("sec-ch-ua");
        headers.remove("sec-ch-ua-mobile");
        headers.remove("sec-ch-ua-platform");
        proxy(req, Some("https://www.baidu.com".parse().unwrap())).await
    });
    let serve_proxy = get_service(proxy_service).handle_error(handle_error_hyper);
    dotenv().ok();

    let router_svc = Router::new()
        .route_service("/proxy", serve_proxy)
        .fallback_service(serve_dir);

    tracing::info!("listening on {}", port);
    serve(router_svc, port).await;
}

/// 代理请求
async fn proxy(req: Request<Body>, host_addr: Option<Uri>) -> Result<Response, hyper::Error> {
    tracing::debug!(?req);

    match req.method() {
        &Method::CONNECT => {
            if let Some(host_addr) = host_addr
                .unwrap_or(req.uri().clone())
                .authority()
                .map(|auth| auth.to_string())
            {
                tokio::task::spawn(async move {
                    match hyper::upgrade::on(req).await {
                        Ok(upgraded) => {
                            if let Err(e) = tunnel(upgraded, host_addr).await {
                                tracing::warn!("server io error: {}", e);
                            };
                        }
                        Err(e) => tracing::warn!("upgrade error: {}", e),
                    }
                });
                Ok(Response::new(body::boxed(body::Empty::new())))
            } else {
                tracing::warn!("CONNECT host is not socket addr: {:?}", req.uri());
                Ok((
                    StatusCode::BAD_REQUEST,
                    "CONNECT must be to a socket address",
                )
                    .into_response())
            }
        }
        _ => {
            let path_rewirte = host_addr.unwrap().to_string() + &req.uri().path().replace("/proxy", "");
            println!("{path_rewirte} path_rewirte");
            let client = reqwest::Client::new();
            let (mut parts, body) = req.into_parts();
            parts.headers.clear();
            let req_proxy = client.request(parts.method.clone(), path_rewirte)
            .body(body);
            match req_proxy.send().await {
                Ok(v) => {
                    let  header = v.headers().clone();
                    match v.bytes().await {
                        Ok(b) => {
                            Ok((header ,b).into_response())
                        },
                        Err(e) => {
                            Ok((
                                e.status().unwrap(),
                                "代理失败",
                            )
                                .into_response())
                        },
                    }
                },
                Err(e) => {
                    Ok((
                        e.status().unwrap(),
                        "代理失败",
                    )
                        .into_response())
                },
            }
        }
    }
}

/// 代理通道
async fn tunnel(mut upgraded: Upgraded, addr: String) -> std::io::Result<()> {
    let mut server = TcpStream::connect(addr).await?;

    let (from_client, from_server) =
        tokio::io::copy_bidirectional(&mut upgraded, &mut server).await?;

    tracing::info!(
        "client wrote {} bytes and received {} bytes",
        from_client,
        from_server
    );

    Ok(())
}

/// 资源出错
async fn handle_error(_err: io::Error) -> impl IntoResponse {
    (StatusCode::INTERNAL_SERVER_ERROR, "Something went wrong...")
}

/// 开启服务
async fn serve(app: Router, port: u16) {
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    tracing::debug!("listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app.layer(TraceLayer::new_for_http()).into_make_service())
        .await
        .unwrap();
}

/// 代理错误
async fn handle_error_hyper(_err: hyper::Error) -> impl IntoResponse {
    (StatusCode::INTERNAL_SERVER_ERROR, "Something went wrong...")
}
