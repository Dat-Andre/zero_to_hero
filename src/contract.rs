#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    to_binary, Binary, Deps, DepsMut, Env, MessageInfo, Order, Response, StdResult,
};
use cw2::set_contract_version;

use crate::error::ContractError;
use crate::msg::{
    AllPollsResponse, ConfigResponse, ExecuteMsg, InstantiateMsg, PollResponse, QueryMsg,
    UserVotesResponse, VoteResponse,
};

use crate::state::{Ballot, Config, Poll, BALLOTS, CONFIG, POLLS};

const CONTRACT_NAME: &str = "crates.io:cw-starter";
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;
    let admin = msg.admin.unwrap_or_else(|| info.sender.to_string());
    let validated_admin = deps.api.addr_validate(&admin)?;
    let config = Config {
        admin: validated_admin.clone(),
    };
    CONFIG.save(deps.storage, &config)?;
    Ok(Response::new()
        .add_attribute("action", "instantiate")
        .add_attribute("admin", validated_admin.to_string()))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::CreatePoll {
            poll_id,
            question,
            options,
        } => execute_create_poll(deps, _env, info, poll_id, question, options),
        ExecuteMsg::Vote { poll_id, vote } => execute_vote(deps, _env, info, poll_id, vote),
        ExecuteMsg::DeletePoll { poll_id } => execute_delete_poll(deps, _env, info, poll_id),
        ExecuteMsg::RevokeVote { poll_id } => execute_revoke_vote(deps, _env, info, poll_id),
    }
}

fn execute_create_poll(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    poll_id: String,
    question: String,
    options: Vec<String>,
) -> Result<Response, ContractError> {
    if options.len() > 10 {
        return Err(ContractError::TooManyOptions {});
    }

    let mut opts: Vec<(String, u64)> = vec![];
    for opt in options {
        opts.push((opt, 0));
    }

    let poll = Poll {
        creator: info.sender.clone(),
        question,
        options: opts,
    };
    POLLS.save(deps.storage, poll_id.clone(), &poll)?;
    Ok(Response::new()
        .add_attribute("action", "create_poll")
        .add_attribute("poll_id", poll_id)
        .add_attribute("creator", info.sender))
}

fn execute_vote(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    poll_id: String,
    vote: String,
) -> Result<Response, ContractError> {
    let poll = POLLS.may_load(deps.storage, poll_id.clone())?;

    match poll {
        Some(mut poll) => {
            BALLOTS.update(
                deps.storage,
                (info.sender, poll_id.clone()),
                |ballot| -> StdResult<Ballot> {
                    match ballot {
                        Some(ballot) => {
                            let position_of_old_vote = poll
                                .options
                                .iter()
                                .position(|option| option.0 == ballot.option)
                                .unwrap();

                            poll.options[position_of_old_vote].1 -= 1;

                            Ok(Ballot {
                                option: vote.clone(),
                            })
                        }
                        None => Ok(Ballot {
                            option: vote.clone(),
                        }),
                    }
                },
            )?;
            let position = poll.options.iter().position(|option| option.0 == vote);
            if position.is_none() {
                return Err(ContractError::OptionNotFound {});
            }
            let position = position.unwrap();
            poll.options[position].1 += 1;

            POLLS.save(deps.storage, poll_id, &poll)?;
            Ok(Response::new()
                .add_attribute("action", "vote")
                .add_attribute("option", vote))
        }
        None => Err(ContractError::PollNotFound {}),
    }
}

fn execute_delete_poll(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    poll_id: String,
) -> Result<Response, ContractError> {
    // This action should only be allowed to be done by the creator of the poll
    let poll = POLLS.may_load(deps.storage, poll_id.clone())?;

    match poll {
        Some(poll) => {
            if info.sender != poll.creator {
                return Err(ContractError::Unauthorized {});
            }

            POLLS.remove(deps.storage, poll_id);
            Ok(Response::new())
        }
        None => Err(ContractError::Unauthorized {}),
    }
}

fn execute_revoke_vote(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    poll_id: String,
) -> Result<Response, ContractError> {
    let poll = POLLS.may_load(deps.storage, poll_id.clone())?;

    match poll {
        Some(_) => {
            let ballot = BALLOTS.may_load(deps.storage, (info.sender.clone(), poll_id.clone()))?;

            match ballot {
                Some(_) => {
                    BALLOTS.remove(deps.storage, (info.sender, poll_id));
                    Ok(Response::new())
                }
                None => Err(ContractError::Unauthorized {}),
            }
        }
        None => Err(ContractError::Unauthorized {}),
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::AllPolls {} => query_all_polls(deps, env),
        QueryMsg::Poll { poll_id } => query_poll(deps, env, poll_id),
        QueryMsg::Vote { address, poll_id } => query_vote(deps, env, address, poll_id),
        QueryMsg::Config {} => query_config(deps, env),
        QueryMsg::UserVotes { address } => query_all_user_votes(deps, env, address),
    }
}

fn query_all_user_votes(deps: Deps, _env: Env, address: String) -> StdResult<Binary> {
    let validated_address = deps.api.addr_validate(&address).unwrap();

    let votes = BALLOTS
        .prefix(validated_address)
        .range_raw(deps.storage, None, None, Order::Ascending)
        .map(|p| Ok(p?.1))
        .collect::<StdResult<Vec<_>>>()?;

    to_binary(&UserVotesResponse { votes })
}

fn query_config(deps: Deps, _env: Env) -> StdResult<Binary> {
    let config = CONFIG.load(deps.storage)?;

    to_binary(&ConfigResponse { config })
}

fn query_vote(deps: Deps, _env: Env, address: String, poll_id: String) -> StdResult<Binary> {
    let validated_address = deps.api.addr_validate(&address).unwrap();

    let vote = BALLOTS.may_load(deps.storage, (validated_address, poll_id))?;

    to_binary(&VoteResponse { vote })
}

fn query_poll(deps: Deps, _env: Env, poll_id: String) -> StdResult<Binary> {
    let poll = POLLS.may_load(deps.storage, poll_id)?;

    to_binary(&PollResponse { poll })
}

fn query_all_polls(deps: Deps, _env: Env) -> StdResult<Binary> {
    let polls = POLLS
        .range(deps.storage, None, None, Order::Ascending)
        .map(|p| Ok(p?.1))
        .collect::<StdResult<Vec<_>>>()?;

    to_binary(&AllPollsResponse { polls })
}

#[cfg(test)]
mod tests {

    use crate::contract::{execute, instantiate};
    use crate::error::*;
    use crate::msg::{
        AllPollsResponse, ConfigResponse, ExecuteMsg, InstantiateMsg, PollResponse, QueryMsg,
        UserVotesResponse, VoteResponse,
    };
    use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};
    use cosmwasm_std::{attr, from_binary};

    use super::query;

    pub const ADDR1: &str = "addr1";
    pub const ADDR2: &str = "addr2";

    #[test]
    fn test_instantiate() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(ADDR1, &[]);

        let msg = InstantiateMsg { admin: None };

        let res = instantiate(deps.as_mut(), env, info, msg).unwrap();

        assert_eq!(
            res.attributes,
            vec![attr("action", "instantiate"), attr("admin", ADDR1)]
        )
    }

    #[test]
    fn test_instantiate_with_admin() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(ADDR1, &[]);

        let msg = InstantiateMsg {
            admin: Some(ADDR2.to_string()),
        };

        let res = instantiate(deps.as_mut(), env, info, msg).unwrap();

        assert_eq!(
            res.attributes,
            vec![attr("action", "instantiate"), attr("admin", ADDR2)]
        )
    }

    #[test]
    fn test_execute_create_poll_valid() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(ADDR1, &[]);
        let msg = InstantiateMsg { admin: None };
        let _res = instantiate(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();

        let msg = ExecuteMsg::CreatePoll {
            poll_id: "dat_id".to_string(),
            question: "What is your fav Cosmos chain?".to_string(),
            options: vec![
                "Juno".to_string(),
                "Osmosis".to_string(),
                "Stargaze".to_string(),
            ],
        };

        let res = execute(deps.as_mut(), env, info, msg).unwrap();

        assert_eq!(
            res.attributes,
            vec![
                attr("action", "create_poll"),
                attr("poll_id", "dat_id"),
                attr("creator", ADDR1)
            ]
        )
    }

    #[test]
    fn test_execute_create_poll_invalid() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(ADDR1, &[]);
        let msg = InstantiateMsg { admin: None };
        let _res = instantiate(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();

        let msg = ExecuteMsg::CreatePoll {
            poll_id: "some_id".to_string(),
            question: "What's your favourite number?".to_string(),
            options: vec![
                "1".to_string(),
                "2".to_string(),
                "3".to_string(),
                "4".to_string(),
                "5".to_string(),
                "6".to_string(),
                "7".to_string(),
                "8".to_string(),
                "9".to_string(),
                "10".to_string(),
                "11".to_string(),
            ],
        };

        let err = execute(deps.as_mut(), env, info, msg).unwrap_err();

        assert_eq!(ContractError::TooManyOptions {}, err)
    }

    #[test]
    fn test_execute_vote_valid() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(ADDR1, &[]);
        let msg = InstantiateMsg { admin: None };
        let _res = instantiate(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();

        let msg = ExecuteMsg::CreatePoll {
            poll_id: "dat_id".to_string(),
            question: "What is your fav Cosmos chain?".to_string(),
            options: vec![
                "Juno".to_string(),
                "Osmosis".to_string(),
                "Stargaze".to_string(),
            ],
        };

        let _res = execute(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();

        let msg = ExecuteMsg::Vote {
            poll_id: "dat_id".to_string(),
            vote: "Juno".to_string(),
        };

        let res = execute(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();

        assert_eq!(
            res.attributes,
            vec![attr("action", "vote"), attr("option", "Juno")]
        );
        let msg = ExecuteMsg::Vote {
            poll_id: "dat_id".to_string(),
            vote: "Stargaze".to_string(),
        };

        let res = execute(deps.as_mut(), env, info, msg).unwrap();

        assert_eq!(
            res.attributes,
            vec![attr("action", "vote"), attr("option", "Stargaze")]
        )
    }

    #[test]
    fn test_execute_vote_invalid() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(ADDR1, &[]);
        let msg = InstantiateMsg { admin: None };
        let _res = instantiate(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();

        let msg = ExecuteMsg::Vote {
            poll_id: "dat".to_string(),
            vote: "Juno".to_string(),
        };

        let err = execute(deps.as_mut(), env.clone(), info.clone(), msg).unwrap_err();

        assert_eq!(ContractError::PollNotFound {}, err);

        let msg = ExecuteMsg::CreatePoll {
            poll_id: "dat_id".to_string(),
            question: "What is your fav Cosmos chain?".to_string(),
            options: vec![
                "Juno".to_string(),
                "Osmosis".to_string(),
                "Stargaze".to_string(),
            ],
        };

        let _res = execute(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();

        let msg = ExecuteMsg::Vote {
            poll_id: "dat_id".to_string(),
            vote: "Atom".to_string(),
        };

        let err = execute(deps.as_mut(), env, info, msg).unwrap_err();

        assert_eq!(ContractError::OptionNotFound {}, err)
    }

    #[test]
    fn test_query_all_polls() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(ADDR1, &[]);
        let msg = InstantiateMsg { admin: None };
        let _res = instantiate(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();

        let msg = ExecuteMsg::CreatePoll {
            poll_id: "dat_id".to_string(),
            question: "What is your fav Cosmos chain?".to_string(),
            options: vec![
                "Juno".to_string(),
                "Osmosis".to_string(),
                "Stargaze".to_string(),
            ],
        };

        let _res = execute(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();

        let msg = ExecuteMsg::CreatePoll {
            poll_id: "dat_id_2".to_string(),
            question: "What's your club?".to_string(),
            options: vec![
                "Benfica".to_string(),
                "Sporting".to_string(),
                "Porto".to_string(),
            ],
        };
        let _res = execute(deps.as_mut(), env.clone(), info, msg).unwrap();

        // Query
        let msg = QueryMsg::AllPolls {};
        let bin = query(deps.as_ref(), env, msg).unwrap();
        let res: AllPollsResponse = from_binary(&bin).unwrap();

        assert_eq!(res.polls.len(), 2);
    }

    #[test]
    fn test_query_all_polls_with_none() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(ADDR1, &[]);
        let msg = InstantiateMsg { admin: None };
        let _res = instantiate(deps.as_mut(), env.clone(), info, msg).unwrap();

        let msg = QueryMsg::AllPolls {};
        let bin = query(deps.as_ref(), env, msg).unwrap();
        let res: AllPollsResponse = from_binary(&bin).unwrap();

        assert_eq!(res.polls.len(), 0);
    }

    #[test]
    fn test_query_poll() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(ADDR1, &[]);
        let msg = InstantiateMsg { admin: None };
        let _res = instantiate(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();

        let msg = ExecuteMsg::CreatePoll {
            poll_id: "dat_id".to_string(),
            question: "What is your fav Cosmos chain?".to_string(),
            options: vec![
                "Juno".to_string(),
                "Osmosis".to_string(),
                "Stargaze".to_string(),
            ],
        };

        let _res = execute(deps.as_mut(), env.clone(), info, msg).unwrap();

        let msg = QueryMsg::Poll {
            poll_id: "dat_id".to_string(),
        };
        let bin = query(deps.as_ref(), env, msg).unwrap();
        let res: PollResponse = from_binary(&bin).unwrap();

        assert!(res.poll.is_some());
    }

    #[test]
    fn test_query_invalid_poll() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(ADDR1, &[]);
        let msg = InstantiateMsg { admin: None };
        let _res = instantiate(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();

        let msg = ExecuteMsg::CreatePoll {
            poll_id: "dat_id".to_string(),
            question: "What is your fav Cosmos chain?".to_string(),
            options: vec![
                "Juno".to_string(),
                "Osmosis".to_string(),
                "Stargaze".to_string(),
            ],
        };

        let _res = execute(deps.as_mut(), env.clone(), info, msg).unwrap();

        let msg = QueryMsg::Poll {
            poll_id: "dat_what".to_string(),
        };
        let bin = query(deps.as_ref(), env, msg).unwrap();
        let res: PollResponse = from_binary(&bin).unwrap();

        assert!(res.poll.is_none());
    }

    #[test]
    fn test_query_vote() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(ADDR1, &[]);
        let msg = InstantiateMsg { admin: None };
        let _res = instantiate(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();

        let msg = ExecuteMsg::CreatePoll {
            poll_id: "dat_id".to_string(),
            question: "What is your fav Cosmos chain?".to_string(),
            options: vec![
                "Juno".to_string(),
                "Osmosis".to_string(),
                "Stargaze".to_string(),
            ],
        };

        let _res = execute(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();

        let msg = ExecuteMsg::Vote {
            poll_id: "dat_id".to_string(),
            vote: "Juno".to_string(),
        };
        let _res = execute(deps.as_mut(), env.clone(), info, msg).unwrap();

        let msg = QueryMsg::Vote {
            poll_id: "dat_id".to_string(),
            address: ADDR1.to_string(),
        };

        let bin = query(deps.as_ref(), env.clone(), msg).unwrap();
        let res: VoteResponse = from_binary(&bin).unwrap();

        assert!(res.vote.is_some());

        let msg = QueryMsg::Vote {
            poll_id: "dat_what".to_string(),
            address: ADDR2.to_string(),
        };

        let bin = query(deps.as_ref(), env, msg).unwrap();
        let res: VoteResponse = from_binary(&bin).unwrap();
        assert!(res.vote.is_none());
    }

    #[test]
    fn test_query_config() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(ADDR1, &[]);
        let msg = InstantiateMsg { admin: None };
        let _res = instantiate(deps.as_mut(), env.clone(), info, msg).unwrap();

        let msg = QueryMsg::Config {};

        let bin = query(deps.as_ref(), env, msg).unwrap();
        let res: ConfigResponse = from_binary(&bin).unwrap();

        assert_eq!(res.config.admin, ADDR1)
    }

    #[test]
    fn test_query_user_vote() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(ADDR1, &[]);
        let info2 = mock_info(ADDR2, &[]);
        let msg = InstantiateMsg { admin: None };
        let _res = instantiate(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();

        let msg = ExecuteMsg::CreatePoll {
            poll_id: "dat_id".to_string(),
            question: "What is your fav Cosmos chain?".to_string(),
            options: vec![
                "Juno".to_string(),
                "Osmosis".to_string(),
                "Stargaze".to_string(),
            ],
        };
        let _res = execute(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();

        let msg = ExecuteMsg::CreatePoll {
            poll_id: "dat_id_2".to_string(),
            question: "What's your club?".to_string(),
            options: vec![
                "Benfica".to_string(),
                "Sporting".to_string(),
                "Porto".to_string(),
            ],
        };
        let _res = execute(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();

        let msg = ExecuteMsg::Vote {
            poll_id: "dat_id".to_string(),
            vote: "Juno".to_string(),
        };
        let _res = execute(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();

        let msg = ExecuteMsg::Vote {
            poll_id: "dat_id_2".to_string(),
            vote: "Benfica".to_string(),
        };
        let _res = execute(deps.as_mut(), env.clone(), info, msg).unwrap();

        // next vote, should not appear in the assert count bc it is done with a diff address
        let msg = ExecuteMsg::Vote {
            poll_id: "dat_id".to_string(),
            vote: "Stargaze".to_string(),
        };
        let _res = execute(deps.as_mut(), env.clone(), info2, msg).unwrap();

        let msg = QueryMsg::UserVotes {
            address: ADDR1.to_string(),
        };
        let bin = query(deps.as_ref(), env, msg).unwrap();
        let res: UserVotesResponse = from_binary(&bin).unwrap();

        assert_eq!(res.votes.len(), 2);
    }
}
