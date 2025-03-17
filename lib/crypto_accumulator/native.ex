defmodule CryptoAccumulator.Native do
  @moduledoc false

  @version Mix.Project.config()[:version]

  use RustlerPrecompiled,
    otp_app: :crypto_accumulator,
    crate: "crypto_accumulator",
    base_url: "https://github.com/archethic-foundation/crypto-accumulator/releases/download/#{@version}",
    force_build: System.get_env("FORCE_BUILD") in ["1", "true"],
    targets:
      Enum.uniq(["aarch64-unknown-linux-musl" | RustlerPrecompiled.Config.default_targets()]),
    version: @version,
    nif_versions: ~w(2.16)

  def generate_key(), do: :erlang.nif_error(:nif_not_loaded)
  def new_accumulator(_secret_key), do: :erlang.nif_error(:nif_not_loaded)
  def export_accumulator(_accumulator), do: :erlang.nif_error(:nif_not_loaded)

  def add_element(_accumulator, _message), do: :erlang.nif_error(:nif_not_loaded)

  def get_membership_proof(_accumulator, _message), do: :erlang.nif_error(:nif_not_loaded)
  def verify_membership_proof(_accumulator, _proof, _nonce),
    do: :erlang.nif_error(:nif_not_loaded)

  # def get_non_membership_proof(_accumulator, _message), do: :erlang.nif_error(:nif_not_loaded)
  # def verify_non_membership_proof(_accumulator, _proof, _nonce), do: :erlang.nif_error(:nif_not_loaded)
end
