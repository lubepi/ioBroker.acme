import React from 'react';
import { ConfigGeneric, type ConfigGenericProps, type ConfigGenericState } from '@iobroker/json-config';
interface AcmeComponentState extends ConfigGenericState {
    collections: Record<string, {
        tsExpires: number;
        staging: string;
        domains: string[];
    }> | null;
}
export default class AcmeComponent extends ConfigGeneric<ConfigGenericProps, AcmeComponentState> {
    constructor(props: ConfigGenericProps);
    componentDidMount(): Promise<void>;
    readData(obj?: ioBroker.Object): Promise<void>;
    componentWillUnmount(): Promise<void>;
    onCertsChanged: (id: string, obj: ioBroker.Object | null | undefined) => void;
    renderItem(): React.JSX.Element;
}
export {};
