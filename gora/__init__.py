import sys
import os
import hashlib
import uuid
import base64
import re
import time
import struct
import json
import subprocess
import pyteal as pt
import beaker as bk
import algosdk as asdk

from typing import Literal as L
from .inline import InlineAssembly

"""
Return environment variable value or a default if it's not defined.
"""
def get_env(var, defl=None):
    val = os.environ.get(var)
    if val is None:
        if defl is None:
            raise Exception("Required environment variable not set: " + var)
        else:
            val = defl
    return val

algod_defl_port = "4001"
cli_tool_ver = get_env("GORA_DEV_VER", "latest-release")
cli_tool_url = f'https://download.gora.io/{cli_tool_ver}/linux/gora'
cli_tool_path = get_env("GORA_DEV_CLI_TOOL", "./gora_cli")
cfg_path = get_env("GORA_DEV_CONFIG_FILE", "./.gora")

gora_token_deposit_amount = int(get_env("GORA_DEV_TOKEN_DEPOSIT", 10_000_000_000))
gora_algo_deposit_amount = int(get_env("GORA_DEV_ALGO_DEPOSIT", 10_000_000_000))

script_dir, script_file = os.path.split(os.path.abspath(__file__))
gora_main_abi_spec = open(script_dir + "/main-contract.json", "r").read()
gora_main_app = asdk.abi.Contract.from_json(gora_main_abi_spec)

# ABI method argument specs to build signatures for oracle method calls.
request_method_spec = "(byte[],byte[],uint64,byte[],uint64[],uint64[],address[],(byte[],uint64)[])void"
response_method_spec = "(uint32[],byte[])void"

main_app_info = {}

"""
Load Gora config file for the dev environment.
"""
def load_cfg():
    if not os.path.isfile(cfg_path):
        print(f'Config file "{cfg_path}" not found')
        exit()

    print(f'Loading config from "{cfg_path}"')
    local_cfg = json.load(open(cfg_path))

    gora_net_cfg = local_cfg["blockchain"]["perNetworkConfig"]["override"]
    main_app_info["id"] = gora_net_cfg["appIds"]["main"]
    print("Main app ID:", main_app_info["id"])

    main_app_info["addr"] = asdk.logic.get_application_address(main_app_info["id"])
    addr_decoded = base64.b32decode(main_app_info["addr"] + "======")
    main_app_info["addr_bin"] = addr_decoded[:-4] # remove CRC

# Definitions of structured data types based on Algorand ABI types that are
# used by the oracle.

"""
Oracle source specification for classic (type #1) requests.
"""
class SourceSpec(pt.abi.NamedTuple):
    source_id: pt.abi.Field[pt.abi.Uint32]
    source_arg_list: pt.abi.Field[pt.abi.DynamicArray[pt.abi.DynamicBytes]]
    max_age: pt.abi.Field[pt.abi.Uint32]

"""
Oracle source specification for General URL (type #2) requests.
"""
class SourceSpecUrl(pt.abi.NamedTuple):
    url: pt.abi.Field[pt.abi.DynamicBytes]
    auth_url: pt.abi.Field[pt.abi.DynamicBytes]
    value_expr: pt.abi.Field[pt.abi.DynamicBytes]
    timestamp_expr: pt.abi.Field[pt.abi.DynamicBytes]
    max_age: pt.abi.Field[pt.abi.Uint32]
    value_type: pt.abi.Field[pt.abi.Uint8]
    round_to: pt.abi.Field[pt.abi.Uint8]
    gateway_url: pt.abi.Field[pt.abi.DynamicBytes]
    reserved_0: pt.abi.Field[pt.abi.DynamicBytes]
    reserved_1: pt.abi.Field[pt.abi.DynamicBytes]
    reserved_2: pt.abi.Field[pt.abi.Uint32]
    reserved_3: pt.abi.Field[pt.abi.Uint32]

"""
Oracle source specification for off-chain (type #3) requests.
"""
class SourceSpecOffChain(pt.abi.NamedTuple):
    api_version: pt.abi.Field[pt.abi.Uint32] # Minimum off-chain API version required
    spec_type: pt.abi.Field[pt.abi.Uint8] # executable specification type:
                                          # 0 - in-place code,
                                          # 1 - storage box (8-byte app ID followed by box name)
                                          # 2 - URL
    exec_spec: pt.abi.Field[pt.abi.DynamicBytes] # executable specification
    exec_args: pt.abi.Field[pt.abi.DynamicArray[pt.abi.DynamicBytes]] # input arguments
    reserved_0: pt.abi.Field[pt.abi.DynamicBytes] # reserved for future use
    reserved_1: pt.abi.Field[pt.abi.DynamicBytes]
    reserved_2: pt.abi.Field[pt.abi.Uint32]
    reserved_3: pt.abi.Field[pt.abi.Uint32]

"""
Oracle classic (type #1) request specification.
"""
class RequestSpec(pt.abi.NamedTuple):
    source_specs: pt.abi.Field[pt.abi.DynamicArray[SourceSpec]]
    aggregation: pt.abi.Field[pt.abi.Uint32]
    user_data: pt.abi.Field[pt.abi.DynamicBytes]

"""
Oracle General URL (type #2) request specification.
"""
class RequestSpecUrl(pt.abi.NamedTuple):
    source_specs: pt.abi.Field[pt.abi.DynamicArray[SourceSpecUrl]]
    aggregation: pt.abi.Field[pt.abi.Uint32]
    user_data: pt.abi.Field[pt.abi.DynamicBytes]

"""
Oracle off-chain (type #3) request specification.
"""
class RequestSpecOffChain(pt.abi.NamedTuple):
    source_specs: pt.abi.Field[pt.abi.DynamicArray[SourceSpecOffChain]]
    aggregation: pt.abi.Field[pt.abi.Uint32]
    user_data: pt.abi.Field[pt.abi.DynamicBytes]

"""
Specification of destination called by the oracle when returning data.
"""
class DestinationSpec(pt.abi.NamedTuple):
    app_id: pt.abi.Field[pt.abi.Uint64]
    method: pt.abi.Field[pt.abi.DynamicBytes]

"""
Oracle response body.
"""
class ResponseBody(pt.abi.NamedTuple):
    request_id: pt.abi.Field[pt.abi.StaticBytes[L[32]]]
    requester_addr: pt.abi.Field[pt.abi.Address]
    oracle_value: pt.abi.Field[pt.abi.DynamicBytes]
    user_data: pt.abi.Field[pt.abi.DynamicBytes]
    error_code: pt.abi.Field[pt.abi.Uint32]
    source_errors: pt.abi.Field[pt.abi.Uint64]

"""
Storage box specification.
"""
class BoxType(pt.abi.NamedTuple):
    key: pt.abi.Field[pt.abi.DynamicBytes]
    app_id: pt.abi.Field[pt.abi.Uint64]

"""
Gora-enabled Beaker application.
"""
class Application(bk.Application):

    """
    Add "init_gora" ABI method to setup the app for Gora use.
    """
    def __init__(self, name, state, op_boost = 0):
        super().__init__(name, state=state)

        # Add method to initialize the app for using Gora assets.
        @self.external
        def init_gora(token_ref: pt.abi.Asset, main_app_ref: pt.abi.Application):
            return pt_init_gora()

        # Add dummy methods to use in opcode budget boost trick.
        for i in range(0, op_boost):
            self.external(lambda: pt.Seq(), name=f'op_booster_{i}')

    """
    Extend Beaker's "external()" decorator with Gora response verification and
    decoding.
    """
    def gora_handler(self, handler_func, **kwargs):
        def abi_handler(resp_type: pt.abi.Uint32,
                        resp_body_bytes: pt.abi.DynamicBytes):
            return pt.Seq(
                pt_auth_dest_call(),
                pt_smart_assert(resp_type.get() == pt.Int(1)),
                (resp_body := pt.abi.make(ResponseBody)).decode(resp_body_bytes.get()),
                resp_body.request_id.store_into(
                    request_id := pt.abi.make(pt.abi.StaticBytes[L[32]])
                ),
                resp_body.requester_addr.store_into(
                    requester_addr := pt.abi.make(pt.abi.Address)
                ),
                resp_body.oracle_value.store_into(
                    oracle_value := pt.abi.make(pt.abi.DynamicBytes)
                ),
                resp_body.user_data.store_into(
                    user_data := pt.abi.make(pt.abi.DynamicBytes)
                ),
                resp_body.error_code.store_into(
                    error_code := pt.abi.make(pt.abi.Uint32)
                ),
                resp_body.source_errors.store_into(
                    source_errors := pt.abi.make(pt.abi.Uint64)
                ),
                handler_func(request_id.get(), requester_addr.get(),
                             oracle_value.get(), user_data.get(),
                             error_code.get(), source_errors.get()),
            )
        self.external(abi_handler, name=handler_func.__name__, **kwargs)


"""
Return Gora token asset ID
"""
def get_token_asset_id(algod_client):
    acc_info = algod_client.account_info(main_app_info["addr"])
    return acc_info["assets"][0]["asset-id"]

"""
Setup an Algo deposit with Gora for a given account and app.
"""
def setup_algo_deposit(algod_client, account, app_addr):
    print("Setting up Algo deposit")
    composer = asdk.atomic_transaction_composer.AtomicTransactionComposer()
    unsigned_payment_txn = asdk.transaction.PaymentTxn(
        sender=account.address,
        sp=algod_client.suggested_params(),
        receiver=asdk.logic.get_application_address(main_app_info["id"]),
        amt=gora_algo_deposit_amount,
    )
    signer = asdk.atomic_transaction_composer.AccountTransactionSigner(account.private_key)
    signed_payment_txn = asdk.atomic_transaction_composer.TransactionWithSigner(
        unsigned_payment_txn,
        signer
    )
    composer.add_method_call(
        app_id=main_app_info["id"],
        method=gora_main_app.get_method_by_name("deposit_algo"),
        sender=account.address,
        sp=algod_client.suggested_params(),
        signer=signer,
        method_args=[ signed_payment_txn, app_addr ]
    )
    composer.execute(algod_client, 4)

"""
Setup a token deposit with Gora for a given account and app.
"""
def setup_token_deposit(algod_client, account, app_addr):
    print("Setting up token deposit")
    token_asset_id = get_token_asset_id(algod_client)
    composer = asdk.atomic_transaction_composer.AtomicTransactionComposer()
    unsigned_transfer_txn = asdk.transaction.AssetTransferTxn(
        sender=account.address,
        sp=algod_client.suggested_params(),
        receiver=asdk.logic.get_application_address(main_app_info["id"]),
        index=token_asset_id,
        amt=gora_token_deposit_amount,
    )
    signer = asdk.atomic_transaction_composer.AccountTransactionSigner(account.private_key)
    signed_transfer_txn = asdk.atomic_transaction_composer.TransactionWithSigner(
        unsigned_transfer_txn,
        signer
    )
    composer.add_method_call(
        app_id=main_app_info["id"],
        method=gora_main_app.get_method_by_name("deposit_token"),
        sender=account.address,
        sp=algod_client.suggested_params(),
        signer=signer,
        method_args=[ signed_transfer_txn, token_asset_id, app_addr ]
    )
    composer.execute(algod_client, 4)

"""
Return Algorand storage box name for a Gora request key and requester address.
"""
def get_ora_box_name(req_key, addr):
    pub_key = asdk.encoding.decode_address(addr)
    hash_src = pub_key + req_key
    name_hash = hashlib.new("sha512_256", hash_src)
    return name_hash.digest()

"""
Initialize current Pyteal app for Gora use.
"""
def pt_init_gora():
    return pt.Seq(
        pt.Assert(pt.Txn.sender() == pt.Global.creator_address()),
        pt.InnerTxnBuilder.Begin(),
        pt.InnerTxnBuilder.SetFields({
            pt.TxnField.type_enum: pt.TxnType.AssetTransfer,
            pt.TxnField.xfer_asset: pt.Txn.assets[0],
            pt.TxnField.asset_receiver: pt.Global.current_application_address(),
            pt.TxnField.asset_amount: pt.Int(0)
        }),
        pt.InnerTxnBuilder.Submit(),
        pt.InnerTxnBuilder.Begin(),
        (app_id := pt.abi.Uint64()).set(3),
        pt.InnerTxnBuilder.SetFields({
            pt.TxnField.type_enum: pt.TxnType.ApplicationCall,
            pt.TxnField.application_id: pt.Txn.applications[1],
            pt.TxnField.on_completion: pt.OnComplete.OptIn,
        }),
        pt.InnerTxnBuilder.Submit(),
    )

"""
Confirm that current call to a destination app is coming from Gora.
"""
def pt_auth_dest_call():
    return pt.Seq(
        (caller_creator_addr := pt.AppParam.creator(pt.Global.caller_app_id())),
        pt_smart_assert(caller_creator_addr.value() == pt.Bytes(main_app_info["addr_bin"])),
    )

"""
Assert with a number to indentify it in API error message. The message will be:
"shr arg too big, (1000000%d)" where in "%d" is the line number.
"""
def pt_smart_assert(cond):
    err_line = sys._getframe().f_back.f_lineno # calling line number
    return pt.If(pt.Not(cond)).Then(
        InlineAssembly("int 0\nint {}\nshr\n".format(1000000 + err_line))
    )

"""
Make an oracle request with specified parameters.
"""
def pt_oracle_request(request_type, request_key, specs_list_abi, dest_app,
                      dest_method, aggr, user_data, box_refs, app_refs,
                      asset_refs, account_refs):

    spec_class = [ None, RequestSpec, RequestSpecUrl,
                   RequestSpecOffChain ][request_type]
    return pt.Seq(

        (request_type_abi := pt.abi.Uint64()).set(request_type),
        (aggr_abi := pt.abi.Uint32()).set(aggr),
        (user_data_abi := pt.abi.DynamicBytes()).set(pt.Bytes(user_data)),

        (dest_app_abi := pt.abi.Uint64()).set(
            dest_app or pt.Global.current_application_id()),
        (dest_selector_abi := pt.abi.DynamicBytes()).set(pt.Bytes(dest_method)),
        (dest := pt.abi.make(DestinationSpec)).set(dest_app_abi, dest_selector_abi),
        (dest_abi := pt.abi.DynamicBytes()).set(dest.encode()),

        (box_refs_abi := pt.abi.make(pt.abi.DynamicArray[BoxType])).set(box_refs),
        (asset_refs_abi := pt.abi.make(pt.abi.DynamicArray[pt.abi.Uint64])).set(
            asset_refs),
        (account_refs_abi := pt.abi.make(pt.abi.DynamicArray[pt.abi.Address])).set(
            account_refs),
        (app_refs_abi := pt.abi.make(pt.abi.DynamicArray[pt.abi.Uint64])).set(
            app_refs),

        (request_spec := pt.abi.make(spec_class)).set(
            specs_list_abi, aggr_abi, user_data_abi,
        ),
        (request_spec_abi := pt.abi.DynamicBytes()).set(request_spec.encode()),

        pt.InnerTxnBuilder.Begin(),
        pt.InnerTxnBuilder.MethodCall(
            app_id=pt.Int(main_app_info["id"]),
            method_signature="request" + request_method_spec,
            args=[ request_spec_abi, dest_abi, request_type_abi, request_key,
                   app_refs_abi, asset_refs_abi, account_refs_abi, box_refs_abi ],
        ),
        pt.InnerTxnBuilder.Submit(),
    )

"""
Make a General URL request with one or more URL sources.
"""
def pt_query_general_url(request_key, dest_app, dest_method, specs_params,
                         aggr = 0, user_data = "", box_refs = [],
                         asset_refs = [], account_refs = [], app_refs = []):

    spec_defaults = {
        "timestamp_expr": "",
        "max_age": 0,
        "round_to": 0,
        "auth_url": "",
        "gateway_url": "",
    }

    result = [
        (url_abi := pt.abi.DynamicBytes()).set(""),
        (value_expr_abi := pt.abi.DynamicBytes()).set(""),
        (timestamp_expr_abi := pt.abi.DynamicBytes()).set(""),
        (auth_url_abi := pt.abi.DynamicBytes()).set(""),
        (gateway_url_abi := pt.abi.DynamicBytes()).set(""),
        (max_age_abi := pt.abi.Uint32()).set(pt.Int(0)),
        (value_type_abi := pt.abi.Uint8()).set(pt.Int(0)),
        (round_to_abi := pt.abi.Uint8()).set(pt.Int(0)),
        (reserved_0_abi := pt.abi.DynamicBytes()).set(pt.Bytes("")),
        (reserved_1_abi := pt.abi.DynamicBytes()).set(pt.Bytes("")),
        (reserved_2_abi := pt.abi.Uint32()).set(pt.Int(0)),
        (reserved_3_abi := pt.abi.Uint32()).set(pt.Int(0)),
    ]

    specs_list = []
    for params in specs_params:
        spec = spec_defaults | params

        result.extend([
            url_abi.set(pt.Bytes(spec["url"])),
            value_expr_abi.set(pt.Bytes(spec["value_expr"])),
            timestamp_expr_abi.set(pt.Bytes(spec["timestamp_expr"])),
            auth_url_abi.set(pt.Bytes(spec["auth_url"])),
            gateway_url_abi.set(pt.Bytes(spec["gateway_url"])),
            max_age_abi.set(pt.Int(spec["max_age"])),
            value_type_abi.set(pt.Int(spec["value_type"])),
            round_to_abi.set(pt.Int(spec["round_to"])),

            (spec_abi := pt.abi.make(SourceSpecUrl)).set(
                url_abi, auth_url_abi, value_expr_abi, timestamp_expr_abi,
                max_age_abi, value_type_abi, round_to_abi, gateway_url_abi,
                reserved_0_abi, reserved_1_abi, reserved_2_abi, reserved_3_abi,
            ),
        ]),
        specs_list.append(spec_abi),

    result.extend([
        (specs_list_abi := pt.abi.make(pt.abi.DynamicArray[SourceSpecUrl])).set(
            specs_list),
        pt_oracle_request(2, request_key, specs_list_abi, dest_app, dest_method,
                          aggr, user_data, box_refs, app_refs, asset_refs,
                          account_refs),

    ])

    return pt.Seq(result)

"""
Make an off-chain computation request.
"""
def pt_query_off_chain(request_key, dest_app, dest_method, api_version,
                       spec_type, exec_spec, exec_args = [], user_data = "",
                       box_refs = [], asset_refs = [], account_refs = [],
                       app_refs = []):
    result = [
        (api_version_abi := pt.abi.Uint32()).set(api_version),
        (spec_type_abi := pt.abi.Uint8()).set(spec_type),
        (exec_spec_abi := pt.abi.DynamicBytes()).set(exec_spec),
        (empty_string_abi := pt.abi.DynamicBytes()).set(""),
        (zero_uin32_abi := pt.abi.Uint32()).set(0),
    ]

    exec_args_pre_abi = []
    for arg in exec_args:
        result.append((arg_abi := pt.abi.DynamicBytes()).set(arg)),
        exec_args_pre_abi.append(arg_abi)

    result.extend([
        (exec_args_abi := pt.abi.make(pt.abi.DynamicArray[pt.abi.DynamicBytes])).set(
            exec_args_pre_abi),

        (spec_abi := pt.abi.make(SourceSpecOffChain)).set(
            api_version_abi, spec_type_abi, exec_spec_abi,
            exec_args_abi,
            empty_string_abi, empty_string_abi, zero_uin32_abi, zero_uin32_abi,
        ),
        (specs_list_abi := pt.abi.make(pt.abi.DynamicArray[SourceSpecOffChain])).set(
            [ spec_abi ]),
        pt_oracle_request(3, request_key, specs_list_abi, dest_app, dest_method,
                          0, user_data, box_refs, app_refs, asset_refs,
                          account_refs),
    ])
    return pt.Seq(result)

"""
Make a classic request with one or more URL sources.
"""
def pt_query_classic(request_key, dest_app, dest_method, specs_params,
                     aggr = 0, user_data = "", box_refs = [],
                     asset_refs = [], account_refs = [], app_refs = []):
    result = [];
    specs_list = []

    for spec in specs_params:
        args_pre_abi = [];
        for arg in spec.get("args", []):
            result.append((arg_abi := pt.abi.DynamicBytes()).set(pt.Bytes(arg)))
            args_pre_abi.append(arg_abi)

        result.extend([
            (id_abi := pt.abi.Uint32()).set(pt.Int(spec["id"])),
            (max_age_abi := pt.abi.Uint32()).set(pt.Int(spec.get("max_age", 0))),
            (args_abi := pt.abi.make(pt.abi.DynamicArray[pt.abi.DynamicBytes])).set(
                args_pre_abi),
            (spec_abi := pt.abi.make(SourceSpec)).set(
                id_abi, args_abi, max_age_abi),
        ])
        specs_list.append(spec_abi)

    result.extend([
        (specs_list_abi := pt.abi.make(pt.abi.DynamicArray[SourceSpec])).set(
            specs_list),
        pt_oracle_request(1, request_key, specs_list_abi, dest_app, dest_method,
                          aggr, user_data, box_refs, app_refs, asset_refs,
                          account_refs),
    ])

    return pt.Seq(result)

"""
Return text description of a numeric oracle response.
"""
def describe_ora_num(packed):

    if packed is None:
        return "None"
    if packed[0] == 0:
        return "NaN"

    int_part = struct.unpack_from('>Q', packed, 1)
    dec_part = struct.unpack_from('>Q', packed, 9)
    prefix = "-" if packed[0] == 2 else ""
    return prefix + str(int_part[0]) + "." + str(dec_part[0])

"""
Return last oracle response as a byte string.
"""
def get_ora_value(algod_client, app_id, addr, key_name = "last_oracle_value",
                  max_time = 10, interval = 0.5):

    print(f"Waiting for for oracle return value (up to {max_time} seconds)")
    key = base64.b64encode(key_name.encode())
    start_time = time.time()

    while time.time() - start_time < max_time:
        app_info = algod_client.account_application_info(addr, app_id)
        global_vars = app_info["created-app"].get("global-state", [])
        value_vars = [ x for x in global_vars if x["key"].encode() == key ]
        if (value_vars):
            value = base64.b64decode(value_vars[0]["value"]["bytes"])
            return value
"""
Return true if dev NR container is running, false otherwise.
"""
def is_dev_nr_running():
    output = run_cli("docker-status", [], { "GORA_CONFIG_FILE": cfg_path })
    return bool(re.search("\nRunning\n$", output))

"""
Run Gora CLI tool.
"""
def run_cli(cli_cmd, args = [], env = {}, is_rt = False):
    cmd = [ cli_tool_path, cli_cmd, *args ]
    print(f'Running: "{" ".join(cmd)}"')
    passed_env = { **os.environ, **env }
    if is_rt:
        subprocess.check_call(cmd, env=passed_env)
    else:
        return subprocess.check_output(cmd, env=passed_env, text=True)

"""
Run a demo script.
"""
def run_demo_app(demo_app, demo_method, is_numeric = False, budget_increase = 0):

    load_cfg()

    # Get Algorand API client instance to talk to local Algorand sandbox node.
    algod_client = bk.localnet.get_algod_client()

    # Pick a local account to use for asset creation and tests.
    account = bk.localnet.get_accounts()[0]
    print("Using local account", account.address)

    # Instantiate ApplicationClient to manage our app.
    app_client = bk.client.ApplicationClient(
        client=algod_client,
        app=demo_app,
        signer=account.signer
    )

    # Deploy our app to the chain.
    print("Deploying the app")
    app_id, app_addr, txid = app_client.create()
    print("Done, txn ID:", txid)
    print("App ID:", app_id)
    print("App address:", app_addr)

    token_asset_id = get_token_asset_id(algod_client)
    print("Token asset ID:", token_asset_id)

    # Supply the app with GORA tokens and ALGO.
    print("Initializing app for GORA")
    app_client.fund(1000000)
    app_client.call(
        method="init_gora",
        token_ref=token_asset_id,
        main_app_ref=main_app_info["id"],
    )
    setup_algo_deposit(algod_client, account, app_addr)
    setup_token_deposit(algod_client, account, app_addr)

    req_key = uuid.uuid4().bytes;
    box_name = get_ora_box_name(req_key, app_addr)

    atc = asdk.atomic_transaction_composer.AtomicTransactionComposer()
    app_client.add_method_call(
        atc=atc,
        method=demo_method,
        request_key=req_key,
        foreign_apps=[ main_app_info["id"] ],
        boxes=[ (main_app_info["id"], box_name) ],
    );

    if budget_increase:
        print(f'Increasing opcode budget by adding {budget_increase} dummy txn(s)')
        for i in range(0, budget_increase):
            app_client.add_method_call(atc, f'op_booster_{i}');

    print("Calling the app")
    result = app_client.execute_atc(atc)

    print("Confirmed in round:", result.confirmed_round)
    print("Top txn ID:", result.tx_ids[-1])

    if is_dev_nr_running():
        print("Detected development Gora node running in the background")
    else:
        print("Background development Gora node not detected, running one temporarily")
        run_cli("docker-start", [], {
            "GORA_CONFIG_FILE": cfg_path,
            "GORA_DEV_ONLY_ROUND": str(result.confirmed_round),
        }, True)

    ora_value = get_ora_value(algod_client, app_id, account.address)
    if (ora_value is None):
        print("No oracle value received")
        return

    value_descr = describe_ora_num(ora_value) if is_numeric else ora_value
    print("Received oracle value:", value_descr)
