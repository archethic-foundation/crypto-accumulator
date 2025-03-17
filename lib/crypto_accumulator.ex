defmodule CryptoAccumulator do
  @moduledoc """
  A cryptographic accumulator implementation based on the RSA accumulator scheme

  It allows to add new elements to the accumulator and verify if a given element is part of the accumulator

  The size of membership proofs is 800 bytes
  A unique nonce is generated for each generated proof
  """

  @doc """
  Generate a new secret key
  """
  @spec generate_key() :: {:ok, binary()} | {:error, binary()}
  def generate_key  do
    CryptoAccumulator.Native.generate_key()
  end

  @doc """
  Generate a new accumulator
  """
  @spec new(secret_key :: binary()) :: {:ok, reference()} | {:error, binary()}
  def new(sk) do
    CryptoAccumulator.Native.new_accumulator(sk)
  end

  @doc """
  Add a new element to the accumulator
  """
  @spec add_element(accumulator :: reference(), value :: binary()) :: :ok | {:error, binary()}
  def add_element(acc, value) do
    CryptoAccumulator.Native.add_element(acc, hash(value))
  end

  @doc """
  Get a membership proof for a given element

  It returns the membership proof and the associated nonce
  """
  @spec get_membership_proof(accumulator :: reference(), value :: binary()) :: {:ok, proof :: binary(), nonce :: binary()} | {:error, binary()}
  def get_membership_proof(acc, value) do
    CryptoAccumulator.Native.get_membership_proof(acc, hash(value))
  end

  @doc """
  Verify a membership proof for a given element and its nonce
  """
  @spec verify_membership_proof(accumulator :: reference(), proof :: binary(), nonce :: binary()) :: {:ok, boolean()} | {:error, binary()}
  def verify_membership_proof(acc, proof, nonce) do
    CryptoAccumulator.Native.verify_membership_proof(acc, proof, nonce)
  end

  @doc """
  Export the accumulator's public information
  """
  @spec export(accumulator :: reference()) :: {:ok, binary()} | {:error, binary()}
  def export(acc) do
    CryptoAccumulator.Native.export_accumulator(acc)
  end

  defp hash(value), do: :crypto.hash(:sha256, value)
end
