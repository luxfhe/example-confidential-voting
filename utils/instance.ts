import { LuxFHEClient, Permit, getPermit } from "luxfhejs";
import { HardhatRuntimeEnvironment } from "hardhat/types/runtime";

export interface FheContract {
  instance: LuxFHEClient;
  permit: Permit;
}

export async function createFheInstance(contractAddress: string, hre: HardhatRuntimeEnvironment): Promise<FheContract> {
  const provider = hre.ethers.provider;

  let instance = new LuxFHEClient({ provider });
  const permit = await getPermit(contractAddress, provider);
  instance.storePermit(permit);
  return { instance, permit };
}
