use std::sync::Arc;

use mail_send::{smtp::AssertReply, SmtpClientBuilder};
use smtp_proto::Severity;
use tokio::sync::{mpsc, oneshot};

use super::lookup::{Event, Item, LoggedUnwrap, Lookup, LookupResult, RemoteLookup};

const MAX_RCPTS_PER_SESSION: usize = 50;
const MAX_AUTH_FAILURES_PER_SESSION: usize = 3;

// TODO use async traits when stabilized
pub async fn lookup_smtp(
    builder: &SmtpClientBuilder<String>,
    mut lookup: Lookup,
    tx: &mpsc::Sender<Event>,
) -> Result<(), mail_send::Error> {
    let mut client = builder.connect().await?;
    let mut sent_mail_from = false;
    let mut num_rcpts = 0;
    let mut num_auth_failures = 0;

    loop {
        let (result, is_reusable): (LookupResult, bool) = match &lookup.item {
            Item::Exists(rcpt_to) => {
                if !sent_mail_from {
                    client
                        .cmd(b"MAIL FROM:<>\r\n")
                        .await?
                        .assert_positive_completion()?;
                    sent_mail_from = true;
                }
                let reply = client
                    .cmd(format!("RCPT TO:<{}>\r\n", rcpt_to).as_bytes())
                    .await?;
                let result = match reply.severity() {
                    Severity::PositiveCompletion => {
                        num_rcpts += 1;
                        LookupResult::True
                    }
                    Severity::PermanentNegativeCompletion => LookupResult::False,
                    _ => return Err(mail_send::Error::UnexpectedReply(reply)),
                };

                // Try to reuse the connection with any queued requests
                (result, num_rcpts < MAX_RCPTS_PER_SESSION)
            }
            Item::Authenticate(credentials) => {
                let result = match client.authenticate(credentials).await {
                    Ok(_) => true,
                    Err(err) => match &err {
                        mail_send::Error::AuthenticationFailed(err) if err.code() == 535 => {
                            num_auth_failures += 1;
                            false
                        }
                        _ => {
                            return Err(err);
                        }
                    },
                };
                (
                    result.into(),
                    !result && num_auth_failures < MAX_AUTH_FAILURES_PER_SESSION,
                )
            }
            Item::Verify(address) | Item::Expand(address) => {
                let reply = client
                    .cmd(
                        if matches!(&lookup.item, Item::Verify(_)) {
                            format!("VRFY {}\r\n", address)
                        } else {
                            format!("EXPN {}\r\n", address)
                        }
                        .as_bytes(),
                    )
                    .await?;
                match reply.code() {
                    250 | 251 => (
                        reply
                            .message()
                            .split('\n')
                            .map(|p| p.to_string())
                            .collect::<Vec<String>>()
                            .into(),
                        true,
                    ),
                    550 | 551 | 553 | 500 | 502 => (LookupResult::False, true),
                    _ => {
                        return Err(mail_send::Error::UnexpectedReply(reply));
                    }
                }
            }
        };

        // Try to reuse the connection with any queued requests
        lookup.result.send(result.clone()).logged_unwrap();
        if is_reusable {
            let (next_lookup_tx, next_lookup_rx) = oneshot::channel::<Option<Lookup>>();
            if tx
                .send(Event::WorkerReady {
                    item: lookup.item,
                    result,
                    next_lookup: next_lookup_tx.into(),
                })
                .await
                .logged_unwrap()
            {
                if let Ok(Some(next_lookup)) = next_lookup_rx.await {
                    lookup = next_lookup;
                    continue;
                }
            }
        } else {
            tx.send(Event::WorkerReady {
                item: lookup.item,
                result,
                next_lookup: None,
            })
            .await
            .logged_unwrap();
        }
        break;
    }

    Ok(())
}

impl RemoteLookup for Arc<SmtpClientBuilder<String>> {
    fn spawn_lookup(&self, lookup: Lookup, tx: mpsc::Sender<Event>) {
        let builder = self.clone();
        tokio::spawn(async move {
            if let Err(err) = lookup_smtp(builder.as_ref(), lookup, &tx).await {
                tracing::warn!(
                    event = "error",
                    class = "remote",
                    remote.addr = &builder.addr,
                    remote.protocol = "smtp",
                    "Remote lookup failed: {}",
                    err
                );
                tx.send(Event::WorkerFailed).await.logged_unwrap();
            }
        });
    }
}