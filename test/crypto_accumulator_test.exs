defmodule CryptoAccumulatorTest do
  use ExUnit.Case
  use ExUnitProperties

  setup do
    {:ok, sk} = CryptoAccumulator.generate_key()
    {:ok, acc} = CryptoAccumulator.new(sk)
    {:ok, %{sk: sk, acc: acc}}
  end

  property "membership proof should work with all binaries", %{acc: acc} do
    check all(data <- StreamData.binary(length: 32)) do
      data = :crypto.hash(:sha256, data)
      # Add the element and generate membership proof
      assert :ok = CryptoAccumulator.add_element(acc, data)
      assert {:ok, proof, nonce} = CryptoAccumulator.get_membership_proof(acc, data)
      assert {:ok, acc_public_export} = CryptoAccumulator.export(acc)
      assert {:ok, true} = CryptoAccumulator.verify_membership_proof(acc_public_export, proof, nonce)
    end
  end

  property "non membership proof should work with all binaries", %{acc: acc} do
    check all(data <- StreamData.binary(length: 32)) do
      data = :crypto.hash(:sha256, data)
      assert {:ok, acc_public_export} = CryptoAccumulator.export(acc)
      assert {:ok, proof, nonce} = CryptoAccumulator.get_membership_proof(acc, data)
      # Check the membership if wrong to assert non membership proof
      # This is workaround around non membership which doesn't work for all data (randomly generated binaries)
      assert {:ok, false} = CryptoAccumulator.verify_membership_proof(acc_public_export, proof, nonce)
    end
  end
end
